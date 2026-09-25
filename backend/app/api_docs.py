from collections.abc import Iterable

from fastapi import APIRouter, Request
from fastapi.openapi.utils import get_openapi
from fastapi.responses import JSONResponse
from fastapi.routing import APIRoute

from .auth import PUBLIC_API_PATHS


router = APIRouter(tags=["API documentation"])
PUBLIC_SCHEMA_PATHS = PUBLIC_API_PATHS | {"/api/health"}
METHODS = {"get", "post", "put", "patch", "delete", "options", "head"}
UPLOAD_BODY = {
    "required": True,
    "content": {"multipart/form-data": {"schema": {
        "type": "object", "required": ["files"],
        "properties": {"files": {
            "type": "array", "minItems": 1,
            "items": {"type": "string", "format": "binary"},
            "description": "One or more Docker or OCI image archives in TAR format.",
        }},
    }}},
}
REPORT_IMPORT_BODY = {
    "required": True,
    "content": {"application/json": {
        "schema": {
            "type": "object", "required": ["format", "format_version", "reports"],
            "properties": {
                "format": {"type": "string", "example": "layerscope-report"},
                "format_version": {"type": "integer", "example": 1},
                "generated_at": {"type": "string", "format": "date-time"},
                "report_count": {"type": "integer", "minimum": 1, "maximum": 100},
                "reports": {"type": "array", "minItems": 1, "maxItems": 100,
                            "items": {"type": "object", "description": "A completed report object from a LayerScope JSON export."}},
            },
        },
        "example": {
            "format": "layerscope-report", "format_version": 1,
            "generated_at": "2026-01-01T00:00:00Z", "report_count": 1,
            "reports": [{"image_id": 1, "image_key": "0" * 64, "image": "example-image.tar",
                         "status": "completed", "finished_at": "2026-01-01T00:00:00Z",
                         "counts": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0},
                         "total": 0, "findings": [], "packages": []}],
        },
    }},
}
BRANDED_REPORT_BODY = {
    "required": True,
    "content": {
        "image/png": {"schema": {"type": "string", "format": "binary"}},
        "image/jpeg": {"schema": {"type": "string", "format": "binary"}},
    },
}
EXTRA_OPERATION_DOCS = {
    ("/api/uploads", "post"): {
        "requestBody": UPLOAD_BODY,
        "responses": {"201": {"description": "All archives were validated and added to inventory."}},
    },
    ("/api/reports/import", "post"): {
        "requestBody": REPORT_IMPORT_BODY,
        "responses": {"201": {"description": "The portable report was imported or skipped as a duplicate."}},
    },
    ("/api/exports", "get"): {
        "description": (
            "Download saved scans as LayerScope JSON, standalone HTML, PDF, Elastic ECS 9.5.0 Bulk API NDJSON, "
            "or DefectDojo Generic Findings Import JSON. Compatibility exports are files only and contain no "
            "credentials, host paths, archive paths, or raw Trivy evidence."
        ),
        "responses": {"200": {"description": "A report file in the requested format."}},
    },
    ("/api/exports/branded", "post"): {
        "description": (
            "Create a one-time HTML or PDF export with a PNG or JPEG logo supplied as the raw request body. "
            "The bounded image is decoded, validated, metadata-stripped, re-encoded as PNG, embedded locally, "
            "and never stored. Browser sessions require X-CSRF-Token."
        ),
        "requestBody": BRANDED_REPORT_BODY,
        "responses": {
            "200": {"description": "A branded HTML or PDF report file."},
            "400": {"description": "The image is malformed, animated, mismatched, or outside decoded limits."},
            "413": {"description": "The encoded logo exceeds 2 MiB."},
            "415": {"description": "The request is not PNG or JPEG."},
        },
    },
}


def expanded_routes(routes: Iterable):
    """Expand FastAPI's lazy included-router wrappers for schema metadata inspection."""
    for route in routes:
        original_router = getattr(route, "original_router", None)
        if original_router is not None:
            yield from expanded_routes(original_router.routes)
        else:
            yield route


def dependency_metadata(route: APIRoute):
    roles: set[str] = set()
    session_only = False

    def visit(dependant):
        nonlocal session_only
        call = getattr(dependant, "call", None)
        roles.update(getattr(call, "layerscope_roles", ()))
        session_only = session_only or bool(getattr(call, "layerscope_session_only", False))
        for child in getattr(dependant, "dependencies", ()):
            visit(child)

    visit(route.dependant)
    return sorted(roles), session_only


def default_tag(path: str):
    if path.startswith("/api/auth"):
        return "Authentication"
    if path.startswith("/api/api-tokens"):
        return "API tokens"
    if path.startswith("/api/users"):
        return "Users"
    if path.startswith("/api/groups"):
        return "Groups"
    if path.startswith("/api/components") or path.startswith("/api/component-jobs"):
        return "Components"
    if path.startswith("/api/backups"):
        return "Backups"
    if path.startswith("/api/reports") or path.startswith("/api/exports"):
        return "Reports"
    if path.startswith("/api/uploads") or path.startswith("/api/upload-jobs"):
        return "Uploads"
    if path.startswith("/api/images"):
        return "Images"
    if path.startswith("/api/scans") or path.startswith("/api/jobs"):
        return "Scans and jobs"
    if path.startswith("/api/diagnostics") or path.startswith("/api/service-status") or path.startswith("/api/health"):
        return "Runtime"
    if path.startswith("/api/events"):
        return "Live events"
    return "Dashboard"


def authenticated_openapi(application):
    routes = list(expanded_routes(application.router.routes))
    schema = get_openapi(
        title="LayerScope API",
        version="1.0.0",
        description=(
            "Authenticated local API for LayerScope image inventory, scanning, findings, reports, "
            "component maintenance, users, backups, and runtime diagnostics. Browser sessions use "
            "CSRF protection for mutations; programmatic clients use personal bearer tokens."
        ),
        routes=routes,
    )
    schema["servers"] = [{"url": "/", "description": "Current LayerScope installation"}]
    components = schema.setdefault("components", {})
    security_schemes = components.setdefault("securitySchemes", {})
    security_schemes["BearerAuth"] = {
        "type": "http", "scheme": "bearer", "bearerFormat": "LayerScope personal API token",
        "description": "A one-time-revealed personal token beginning with lsp_.",
    }
    security_schemes["SessionCookie"] = {
        "type": "apiKey", "in": "cookie", "name": "trivy_session",
        "description": "Opaque HttpOnly browser session. Mutations also require X-CSRF-Token.",
    }
    schema["security"] = [{"BearerAuth": []}, {"SessionCookie": []}]

    route_index = {(route.path_format, method.casefold()): route
                   for route in routes if isinstance(route, APIRoute)
                   for method in route.methods}
    for path, path_item in schema.get("paths", {}).items():
        for method, operation in path_item.items():
            if method not in METHODS or not isinstance(operation, dict):
                continue
            route = route_index.get((path, method))
            roles, session_only = dependency_metadata(route) if route else ([], False)
            extra = EXTRA_OPERATION_DOCS.get((path, method), {})
            for key, value in extra.items():
                if key == "responses":
                    operation.setdefault("responses", {}).update(value)
                else:
                    operation.setdefault(key, value)
            public = path in PUBLIC_SCHEMA_PATHS
            if public:
                operation["security"] = []
                operation["x-layerscope-authentication"] = "public"
                operation["x-layerscope-roles"] = []
            elif session_only:
                operation["security"] = [{"SessionCookie": []}]
                operation["x-layerscope-authentication"] = "browser-session-only"
                operation["x-layerscope-roles"] = roles or ["viewer", "operator", "admin"]
            else:
                operation["security"] = [{"BearerAuth": []}, {"SessionCookie": []}]
                operation["x-layerscope-authentication"] = "session-or-bearer"
                operation["x-layerscope-roles"] = roles or ["viewer", "operator", "admin"]
            if not operation.get("tags") or operation["tags"] == ["default"]:
                operation["tags"] = [default_tag(path)]
            if not public:
                operation.setdefault("responses", {}).setdefault("401", {"description": "Authentication required"})
                operation["responses"].setdefault("403", {"description": "Insufficient role, session, origin, or CSRF validation"})
    return schema


@router.get("/api/openapi.json", include_in_schema=False)
def openapi_schema(request: Request):
    return JSONResponse(authenticated_openapi(request.app))
