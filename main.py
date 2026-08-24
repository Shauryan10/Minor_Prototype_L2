from __future__ import annotations

from fastapi import FastAPI

from api.assessment_routes import router as assessment_router


app = FastAPI(
    title="L2 Detection & Risk Assessment",
    version="1.0",
)

app.include_router(assessment_router)


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}
