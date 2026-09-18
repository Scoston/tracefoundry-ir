"""HTTP boundary: strict inputs, authenticated identities, CSRF, and inert rendering."""

import hmac
import os
from pathlib import Path

from fastapi import Depends, FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from starlette.middleware.trustedhost import TrustedHostMiddleware

from . import __version__, models, tools
from .security import sha256, strict_json
from .service import Service
from .store import Fault, Store

MAX_BODY = 4_100_000
STATIC = Path(__file__).parent / "static"


class BoundaryMiddleware:
    def __init__(self, app, service: Service):
        self.app, self.service = app, service

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)

        async def secure_send(message):
            if message["type"] == "http.response.start":
                headers = list(message.get("headers", []))
                headers.extend(
                    [
                        (b"cache-control", b"no-store"),
                        (b"x-content-type-options", b"nosniff"),
                        (b"x-frame-options", b"DENY"),
                        (b"referrer-policy", b"no-referrer"),
                        (
                            b"content-security-policy",
                            b"default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'",
                        ),
                    ]
                )
                message["headers"] = headers
            await send(message)

        if scope["method"] in {"POST", "PUT", "PATCH", "DELETE"}:
            headers = dict(scope["headers"])
            host = headers.get(b"host", b"").decode()
            expected_origin = os.getenv("TFIR_ORIGIN") or scope["scheme"] + "://" + host
            origin = headers.get(b"origin", b"").decode()
            if origin and origin != expected_origin:
                self.service.deny(None, "origin_not_allowed", "request_boundary")
                return await JSONResponse({"error": "origin_not_allowed"}, 403)(
                    scope, receive, secure_send
                )
            body = bytearray()
            while True:
                message = await receive()
                if message["type"] == "http.disconnect":
                    return
                body.extend(message.get("body", b""))
                if len(body) > MAX_BODY:
                    self.service.deny(None, "request_too_large", "request_boundary")
                    return await JSONResponse({"error": "request_too_large"}, 413)(
                        scope, receive, secure_send
                    )
                if not message.get("more_body", False):
                    break
            if body:
                if headers.get(b"content-type", b"").split(b";")[0] != b"application/json":
                    return await JSONResponse({"error": "application_json_required"}, 415)(
                        scope, receive, secure_send
                    )
                try:
                    strict_json(bytes(body))
                except (ValueError, UnicodeError, RecursionError):
                    self.service.deny(None, "invalid_or_ambiguous_json", "request_boundary")
                    return await JSONResponse({"error": "invalid_or_ambiguous_json"}, 422)(
                        scope, receive, secure_send
                    )
            original_receive, delivered = receive, False

            async def cached_receive():
                nonlocal delivered
                if not delivered:
                    delivered = True
                    return {"type": "http.request", "body": bytes(body), "more_body": False}
                return await original_receive()

            receive = cached_receive
        await self.app(scope, receive, secure_send)


def create_app(directory: str | Path | None = None, *, provider=None) -> FastAPI:
    store = Store(Path(directory or os.getenv("TFIR_DATA_DIR", "var")))
    service = Service(store, provider)
    app = FastAPI(
        title="TraceFoundry IR",
        version=__version__,
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )
    app.state.service = service
    app.add_middleware(BoundaryMiddleware, service=service)
    app.add_middleware(
        TrustedHostMiddleware,
        allowed_hosts=os.getenv("TFIR_ALLOWED_HOSTS", "127.0.0.1,localhost,testserver").split(","),
    )

    def actor(request: Request):
        current = store.session(request.cookies.get("tfir_session"))
        request.state.actor = current
        if request.method in {"POST", "PUT", "PATCH", "DELETE"}:
            supplied = request.headers.get("x-csrf-token", "")
            if not supplied or not hmac.compare_digest(
                sha256(supplied.encode()), current["csrf_hash"]
            ):
                raise Fault(403, "csrf_validation_failed")
        return current

    @app.exception_handler(Fault)
    async def fault_handler(request, exc):
        try:
            service.deny(
                getattr(request.state, "actor", None),
                exc.code,
                getattr(request.scope.get("route"), "path", "unmatched_route"),
            )
        except Exception:
            return JSONResponse(
                {"error": "audit_unavailable", "action": "pause_and_investigate"}, 503
            )
        return JSONResponse({"error": exc.code}, exc.status)

    @app.exception_handler(RequestValidationError)
    async def validation_handler(request, exc):
        try:
            service.deny(
                getattr(request.state, "actor", None), "invalid_request", "schema_validation"
            )
        except Exception:
            return JSONResponse({"error": "audit_unavailable"}, 503)
        # Never echo password, uploaded evidence, or failed input fields.
        return JSONResponse(
            {"error": "invalid_request", "fields": [list(e["loc"]) for e in exc.errors()]}, 422
        )

    @app.exception_handler(Exception)
    async def unexpected_handler(request, exc):
        try:
            service.deny(
                getattr(request.state, "actor", None), "internal_operation_failed", "application"
            )
        except Exception:
            return JSONResponse(
                {"error": "audit_unavailable", "action": "pause_and_investigate"}, 503
            )
        return JSONResponse(
            {
                "error": "operation_unavailable",
                "action": "check_integrity_and_execution_status_before_retry",
            },
            503,
        )

    @app.get("/")
    def index():
        return FileResponse(STATIC / "index.html")

    app.mount("/static", StaticFiles(directory=STATIC), name="static")

    @app.get("/health")
    def health():
        return {
            "status": "running",
            "version": __version__,
            "profile": "local-reference-application",
        }

    @app.post("/api/login")
    def login(body: models.Login, request: Request):
        user, token, csrf = store.login(
            body.username, body.password, request.client.host if request.client else "unknown"
        )
        response = JSONResponse({"user": user, "csrf_token": csrf})
        response.set_cookie(
            "tfir_session",
            token,
            max_age=1800,
            httponly=True,
            secure=os.getenv("TFIR_SECURE_COOKIES", "false").lower() == "true",
            samesite="strict",
            path="/",
        )
        return response

    @app.post("/api/logout")
    def logout(current=Depends(actor)):
        with store.transaction("admin-" + current["tenant"]) as c:
            c.execute("DELETE FROM sessions WHERE token_hash=?", (current["session_hash"],))
            store.audit(
                c,
                "admin-" + current["tenant"],
                current,
                "authentication.logged_out",
                {"auth_event": current["auth_event"]},
            )
        response = JSONResponse({"logged_out": True})
        response.delete_cookie("tfir_session", path="/")
        return response

    @app.get("/api/me")
    def me(current=Depends(actor)):
        return {
            "username": current["username"],
            "roles": current["roles"],
            "tenant": current["tenant"],
        }

    @app.get("/api/tools")
    def tool_list(current=Depends(actor)):
        return {
            "policy": tools.POLICY,
            "tool_digest": tools.registry_digest(),
            "model_configured": bool(service.provider.url),
            "tools": [
                {
                    "name": name,
                    "description": description,
                    "required_role_groups": groups,
                    "arguments_schema": model.model_json_schema(),
                }
                for name, (model, groups, description) in tools.REGISTRY.items()
            ],
        }

    @app.get("/api/openapi.json")
    def openapi(current=Depends(actor)):
        return app.openapi()

    @app.get("/api/cases")
    def cases(current=Depends(actor)):
        return service.list_cases(current)

    @app.post("/api/cases", status_code=201)
    def case_create(body: models.CaseCreate, current=Depends(actor)):
        return service.create_case(current, body)

    @app.get("/api/cases/{case_id}")
    def case_detail(case_id: str, current=Depends(actor)):
        return service.detail(current, case_id)

    @app.post("/api/cases/{case_id}/members")
    def member(case_id: str, body: models.MemberAdd, current=Depends(actor)):
        return service.membership(current, case_id, body.username)

    @app.delete("/api/cases/{case_id}/members/{username}")
    def member_remove(case_id: str, username: str, current=Depends(actor)):
        return service.membership(current, case_id, username, remove=True)

    @app.post("/api/cases/{case_id}/evidence", status_code=201)
    def evidence(case_id: str, body: models.EvidenceUpload, current=Depends(actor)):
        return service.stage(current, case_id, body)

    @app.post("/api/cases/{case_id}/decisions", status_code=201)
    def proposal(case_id: str, body: models.Proposal, current=Depends(actor)):
        return service.propose(current, case_id, body)

    @app.post("/api/cases/{case_id}/decisions/{decision_id}/reviews", status_code=201)
    def review(case_id: str, decision_id: str, body: models.Review, current=Depends(actor)):
        return service.review(current, case_id, decision_id, body)

    @app.post("/api/cases/{case_id}/approvals/{approval_id}/revoke")
    def revoke(case_id: str, approval_id: str, body: models.Reason, current=Depends(actor)):
        return service.revoke(current, case_id, approval_id, body.reason)

    @app.post("/api/cases/{case_id}/decisions/{decision_id}/execute")
    def execute(case_id: str, decision_id: str, current=Depends(actor)):
        return service.execute(current, case_id, decision_id)

    @app.get("/api/cases/{case_id}/audit")
    def audit(case_id: str, current=Depends(actor)):
        return service.audit_view(current, case_id)

    @app.get("/api/cases/{case_id}/artifacts/{artifact_id}")
    def download(case_id: str, artifact_id: str, current=Depends(actor)):
        metadata, data = service.artifact_download(current, case_id, artifact_id)
        extension = ".zip" if metadata["kind"] == "export" else ".bin"
        return Response(
            data,
            media_type="application/octet-stream",
            headers={"Content-Disposition": f'attachment; filename="{artifact_id}{extension}"'},
        )

    return app
