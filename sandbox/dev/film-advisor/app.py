"""
Film Advisor — FastAPI REST API with SQLite backend.

Endpoints:
  GET  /health           — liveness check
  GET  /films            — list all films (optional ?genre=&min_rating=)
  GET  /films/{id}       — get film by id
  POST /films            — add a film
  GET  /recommend        — recommend a film by genre/mood
  GET  /stats            — genre stats for MCP tools

Database is created on startup with seed data if empty.
"""
from __future__ import annotations

import os
import random
from contextlib import asynccontextmanager
from typing import Optional

from fastapi import FastAPI, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import Column, Float, Integer, String, select, text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase

DATABASE_URL = os.environ.get("DATABASE_URL", "sqlite+aiosqlite:////workspace/films.db")

engine = create_async_engine(DATABASE_URL, echo=False)
SessionLocal = async_sessionmaker(engine, expire_on_commit=False)


class Base(DeclarativeBase):
    pass


class Film(Base):
    __tablename__ = "films"

    id = Column(Integer, primary_key=True, autoincrement=True)
    title = Column(String, nullable=False)
    year = Column(Integer, nullable=False)
    genre = Column(String, nullable=False)
    director = Column(String, nullable=False)
    rating = Column(Float, nullable=False)
    description = Column(String, nullable=True)


SEED_FILMS = [
    ("The Shawshank Redemption", 1994, "drama", "Frank Darabont", 9.3,
     "Two imprisoned men bond over years, finding solace and eventual redemption."),
    ("The Godfather", 1972, "crime", "Francis Ford Coppola", 9.2,
     "The aging patriarch of an organized crime dynasty transfers control to his reluctant son."),
    ("The Dark Knight", 2008, "action", "Christopher Nolan", 9.0,
     "Batman raises the stakes in his war on crime with the help of Lt. Jim Gordon."),
    ("Pulp Fiction", 1994, "crime", "Quentin Tarantino", 8.9,
     "The lives of two mob hitmen, a boxer, and others intertwine in four tales of violence."),
    ("Inception", 2010, "sci-fi", "Christopher Nolan", 8.8,
     "A thief who steals corporate secrets through dream-sharing technology."),
    ("Parasite", 2019, "thriller", "Bong Joon-ho", 8.5,
     "Greed and class discrimination threaten a symbiotic relationship between two families."),
    ("Spirited Away", 2001, "animation", "Hayao Miyazaki", 8.6,
     "A young girl wanders into a world ruled by gods, witches, and spirits."),
    ("The Matrix", 1999, "sci-fi", "The Wachowskis", 8.7,
     "A computer hacker learns the true nature of his reality and his role in a war against its controllers."),
    ("Schindler's List", 1993, "drama", "Steven Spielberg", 9.0,
     "In German-occupied Poland during World War II, industrialist Oskar Schindler gradually becomes concerned for his Jewish workers."),
    ("Interstellar", 2014, "sci-fi", "Christopher Nolan", 8.7,
     "A team of explorers travel through a wormhole in space to ensure humanity's survival."),
    ("The Grand Budapest Hotel", 2014, "comedy", "Wes Anderson", 8.1,
     "The adventures of Gustave H, a legendary concierge at a famous European hotel."),
    ("Mad Max: Fury Road", 2015, "action", "George Miller", 8.1,
     "In a post-apocalyptic wasteland, a woman rebels against a tyrannical ruler."),
    ("Get Out", 2017, "horror", "Jordan Peele", 7.7,
     "A Black man visits his white girlfriend's family estate, where he discovers unsettling secrets."),
    ("Everything Everywhere All at Once", 2022, "sci-fi", "Daniels", 7.8,
     "An aging Chinese immigrant is swept up in an adventure through parallel universes."),
    ("The Zone of Interest", 2023, "drama", "Jonathan Glazer", 7.4,
     "The commandant of Auschwitz and his wife try to build a dream life next to the camp."),
]


async def init_db() -> None:
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    async with SessionLocal() as session:
        result = await session.execute(select(Film).limit(1))
        if result.first() is None:
            for t, y, g, d, r, desc in SEED_FILMS:
                session.add(Film(title=t, year=y, genre=g, director=d, rating=r, description=desc))
            await session.commit()


@asynccontextmanager
async def lifespan(app: FastAPI):
    await init_db()
    yield


app = FastAPI(title="Film Advisor", version="1.0.0", lifespan=lifespan)


# ─── Pydantic models ──────────────────────────────────────────────────────────

class FilmOut(BaseModel):
    id: int
    title: str
    year: int
    genre: str
    director: str
    rating: float
    description: Optional[str] = None

    model_config = {"from_attributes": True}


class FilmIn(BaseModel):
    title: str = Field(..., min_length=1, max_length=200)
    year: int = Field(..., ge=1888, le=2030)
    genre: str = Field(..., min_length=1, max_length=50)
    director: str = Field(..., min_length=1, max_length=100)
    rating: float = Field(..., ge=0.0, le=10.0)
    description: Optional[str] = Field(None, max_length=500)


# ─── Endpoints ────────────────────────────────────────────────────────────────

@app.get("/health")
async def health():
    return {"status": "ok", "service": "film-advisor"}


@app.get("/films", response_model=list[FilmOut])
async def list_films(
    genre: Optional[str] = Query(None),
    min_rating: Optional[float] = Query(None, ge=0.0, le=10.0),
):
    async with SessionLocal() as session:
        q = select(Film)
        if genre:
            q = q.where(Film.genre == genre.lower())
        if min_rating is not None:
            q = q.where(Film.rating >= min_rating)
        q = q.order_by(Film.rating.desc())
        result = await session.execute(q)
        return [FilmOut.model_validate(f) for f in result.scalars()]


@app.get("/films/{film_id}", response_model=FilmOut)
async def get_film(film_id: int):
    async with SessionLocal() as session:
        result = await session.execute(select(Film).where(Film.id == film_id))
        film = result.scalar_one_or_none()
        if not film:
            raise HTTPException(status_code=404, detail="Film not found")
        return FilmOut.model_validate(film)


@app.post("/films", response_model=FilmOut, status_code=201)
async def add_film(film_in: FilmIn):
    async with SessionLocal() as session:
        film = Film(**film_in.model_dump())
        session.add(film)
        await session.commit()
        await session.refresh(film)
        return FilmOut.model_validate(film)


@app.get("/recommend", response_model=FilmOut)
async def recommend(
    genre: Optional[str] = Query(None),
    min_rating: float = Query(8.0, ge=0.0, le=10.0),
):
    async with SessionLocal() as session:
        q = select(Film).where(Film.rating >= min_rating)
        if genre:
            q = q.where(Film.genre == genre.lower())
        result = await session.execute(q)
        films = list(result.scalars())
        if not films:
            raise HTTPException(status_code=404, detail="No matching films found")
        chosen = random.choice(films)
        return FilmOut.model_validate(chosen)


@app.get("/stats")
async def stats():
    async with SessionLocal() as session:
        result = await session.execute(
            text("SELECT genre, COUNT(*) as count, ROUND(AVG(rating), 2) as avg_rating FROM films GROUP BY genre ORDER BY count DESC")
        )
        rows = result.fetchall()
        return [{"genre": r[0], "count": r[1], "avg_rating": r[2]} for r in rows]


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app:app", host="0.0.0.0", port=8080, reload=False)
