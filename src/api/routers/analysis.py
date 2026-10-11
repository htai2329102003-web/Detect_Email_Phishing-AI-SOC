from uuid import uuid4

from fastapi import APIRouter, File, HTTPException, Request, UploadFile
from starlette.concurrency import run_in_threadpool

from src.agents.graph import agent
from src.api.deps import Analyst, DBSession
from src.parsers.email_parser import MAX_EMAIL_BYTES, EmailParseError
from src.schemas.analysis import AnalysisResponse
from src.schemas.case import PersistedAnalysisResponse
from src.services.cases import persist_analysis
from src.services.observability import EXTERNAL_TOOLS

router = APIRouter()


@router.post("", response_model=PersistedAnalysisResponse)
async def analyze_email(request: Request, user: Analyst, session: DBSession,
                        file: UploadFile = File(...)) -> PersistedAnalysisResponse:
    """Analyze locally, pass both gates, then atomically persist a PENDING case."""
    try:
        if not file.filename or not file.filename.lower().endswith(".eml"):
            raise HTTPException(status_code=415, detail={"code": "UNSUPPORTED_FILE", "message": "Upload a .eml file"})
        if len(file.filename) > 255 or any(ord(char) < 32 or ord(char) == 127 for char in file.filename):
            raise HTTPException(422, detail={"code": "INVALID_FILENAME"})
        content = await file.read(MAX_EMAIL_BYTES + 1)
        if len(content) > MAX_EMAIL_BYTES:
            raise HTTPException(status_code=413, detail={"code": "EMAIL_TOO_LARGE", "message": "Email exceeds 5 MiB"})
        result = await agent.ainvoke({"case_id": str(uuid4()), "raw_email": content, "evidence": [], "errors": []})
    except EmailParseError as exc:
        raise HTTPException(status_code=422, detail={"code": exc.code, "message": str(exc)}) from exc
    finally:
        await file.close()
    response = AnalysisResponse.from_agent_state(result)
    await run_in_threadpool(persist_analysis, session, response, file.filename, user)
    request.state.analysis_summary = {
        "case_id": response.case_id, "label": response.label_candidate, "score": response.score,
        "external_tool_failures": len({item.tool for item in response.evidence
                                       if item.analyzer in EXTERNAL_TOOLS and item.tool_status != "OK"})
        + int(response.rag_status not in {None, "OK"})
        + int(response.verdict_llm_status not in {"DISABLED", "OK"}),
    }
    return PersistedAnalysisResponse(**{**response.model_dump(), "status": "PENDING"})
