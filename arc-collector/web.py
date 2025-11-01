from fastapi import FastAPI, Request, Depends
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
import httpx, time, os, json
from arc_normalizer import normalize_ms, normalize_google, compute_ati
from store import EventStore
from authlib.integrations.starlette_client import OAuth

app = FastAPI()
store = EventStore(os.getenv("ARC_AES_KEY"))
oauth = OAuth()