import os
import bcrypt
import jwt
import requests
import uvicorn
import concurrent.futures
from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo
from typing import Optional

from fastapi import FastAPI, Depends, HTTPException, Header
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from sqlalchemy import create_engine, Column, Integer, String, Float, DateTime, ForeignKey, UniqueConstraint
from sqlalchemy.orm import sessionmaker, declarative_base, Session

# ==========================================
# AYARLAR
# ==========================================
BASLANGIC_BAKIYESI = 100000.0

# ÖNEMLİ: Bunu Render'da ortam değişkeni (Environment Variable) olarak
# JWT_SECRET adıyla kendiniz belirleyin (rastgele uzun bir metin).
JWT_SECRET = os.environ.get("JWT_SECRET", "AQ.Ab8RN6IigESJSn4jC7ndq_VZzxwnmlPP4aaaW9VhR4vwPTpjhw")
JWT_ALGORITMA = "HS256"
JWT_GECERLILIK_GUN = 30

DATABASE_URL = os.environ.get("DATABASE_URL", "sqlite:///./sanal_borsa.db")

engine_kwargs = {}
if DATABASE_URL.startswith("sqlite"):
    engine_kwargs["connect_args"] = {"check_same_thread": False}

engine = create_engine(DATABASE_URL, **engine_kwargs)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

TR_ZAMAN_DILIMI = ZoneInfo("Europe/Istanbul")

# ==========================================
# VERİTABANI MODELLERİ
# ==========================================
class Kullanici(Base):
    __tablename__ = "kullanicilar"
    id = Column(Integer, primary_key=True, index=True)
    kullanici_adi = Column(String, unique=True, index=True, nullable=False)
    sifre_hash = Column(String, nullable=False)
    bakiye = Column(Float, default=BASLANGIC_BAKIYESI)
    olusturulma_tarihi = Column(DateTime, default=lambda: datetime.now(timezone.utc))


class Pozisyon(Base):
    __tablename__ = "pozisyonlar"
    id = Column(Integer, primary_key=True, index=True)
    kullanici_id = Column(Integer, ForeignKey("kullanicilar.id"), nullable=False)
    sembol = Column(String, nullable=False)
    adet = Column(Float, nullable=False, default=0)
    ortalama_maliyet = Column(Float, nullable=False, default=0)
    __table_args__ = (UniqueConstraint("kullanici_id", "sembol", name="tekil_kullanici_sembol"),)


class Islem(Base):
    __tablename__ = "islemler"
    id = Column(Integer, primary_key=True, index=True)
    kullanici_id = Column(Integer, ForeignKey("kullanicilar.id"), nullable=False)
    sembol = Column(String, nullable=False)
    tur = Column(String, nullable=False)  # "AL" veya "SAT"
    adet = Column(Float, nullable=False)
    fiyat = Column(Float, nullable=False)
    toplam_tutar = Column(Float, nullable=False)
    tarih = Column(DateTime, default=lambda: datetime.now(timezone.utc))


class PortfoyGecmisi(Base):
    __tablename__ = "portfoy_gecmisi"
    id = Column(Integer, primary_key=True, index=True)
    kullanici_id = Column(Integer, ForeignKey("kullanicilar.id"), nullable=False)
    tarih = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    toplam_deger = Column(Float, nullable=False)


Base.metadata.create_all(bind=engine)


def db_al():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# ==========================================
# FASTAPI UYGULAMASI
# ==========================================
app = FastAPI()
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/")
def ana_sayfa():
    return {"mesaj": "Sanal Borsa Motoru Aktif"}


# ==========================================
# YARDIMCI FONKSİYONLAR
# ==========================================
def sifre_hashle(sifre: str) -> str:
    return bcrypt.hashpw(sifre.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def sifre_dogrula(sifre: str, sifre_hash: str) -> bool:
    try:
        return bcrypt.checkpw(sifre.encode("utf-8"), sifre_hash.encode("utf-8"))
    except Exception:
        return False


def token_uret(kullanici_id: int) -> str:
    payload = {
        "sub": str(kullanici_id),
        "exp": datetime.now(timezone.utc) + timedelta(days=JWT_GECERLILIK_GUN),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITMA)


def guncel_fiyat_getir(sembol: str) -> Optional[float]:
    sembol_saf = sembol.replace(".IS", "").upper()
    url = f"https://query2.finance.yahoo.com/v8/finance/chart/{sembol_saf}.IS?interval=1d&range=1d"
    try:
        r = requests.get(url, headers={"User-Agent": "Mozilla/5.0"}, timeout=8)
        if r.status_code != 200:
            return None
        data = r.json()
        result = data.get("chart", {}).get("result")
        if not result:
            return None
        fiyat = result[0].get("meta", {}).get("regularMarketPrice")
        return float(fiyat) if fiyat is not None else None
    except Exception:
        return None


def piyasa_acik_mi():
    """
    BIST normal seans saatlerini kontrol eder: Hafta içi 10:00 - 18:00 (TR saati).
    NOT: Resmi tatiller bu kontrolde YER ALMIYOR (örn. 23 Nisan, 1 Mayıs vb.) —
    sadece hafta sonu + saat kontrolü yapılıyor. Tam bir tatil takvimi eklemek
    istersen ileride burayı genişletebiliriz.
    """
    simdi = datetime.now(TR_ZAMAN_DILIMI)
    if simdi.weekday() >= 5:  # 5=Cumartesi, 6=Pazar
        return False, "Borsa hafta sonu kapalı. BIST işlem saatleri: hafta içi 10:00 - 18:00 (TR saati)."
    acilis = simdi.replace(hour=10, minute=0, second=0, microsecond=0)
    kapanis = simdi.replace(hour=18, minute=0, second=0, microsecond=0)
    if simdi < acilis or simdi >= kapanis:
        return False, "Şu anda mesai saatleri dışındayız. BIST işlem saatleri: hafta içi 10:00 - 18:00 (TR saati)."
    return True, "Piyasa açık."


def gecerli_kullanici(authorization: str = Header(None), db: Session = Depends(db_al)) -> Kullanici:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Oturum bulunamadı. Lütfen giriş yapın.")
    token = authorization.replace("Bearer ", "").strip()
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITMA])
        kullanici_id = int(payload.get("sub"))
    except Exception:
        raise HTTPException(status_code=401, detail="Oturum süresi dolmuş veya geçersiz. Lütfen tekrar giriş yapın.")
    kullanici = db.query(Kullanici).filter(Kullanici.id == kullanici_id).first()
    if not kullanici:
        raise HTTPException(status_code=401, detail="Kullanıcı bulunamadı.")
    return kullanici


def portfoy_ozet_olustur(kullanici: Kullanici, db: Session) -> dict:
    pozisyonlar = db.query(Pozisyon).filter(Pozisyon.kullanici_id == kullanici.id, Pozisyon.adet > 0).all()

    fiyatlar = []
    if pozisyonlar:
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
            fiyatlar = list(executor.map(lambda p: guncel_fiyat_getir(p.sembol), pozisyonlar))

    pozisyon_listesi = []
    toplam_pozisyon_degeri = 0.0

    for pozisyon, canli_fiyat in zip(pozisyonlar, fiyatlar):
        fiyat = canli_fiyat if canli_fiyat is not None else pozisyon.ortalama_maliyet
        guncel_deger = fiyat * pozisyon.adet
        maliyet = pozisyon.ortalama_maliyet * pozisyon.adet
        kar_zarar = guncel_deger - maliyet
        kar_zarar_yuzde = (kar_zarar / maliyet * 100) if maliyet > 0 else 0.0

        toplam_pozisyon_degeri += guncel_deger
        pozisyon_listesi.append({
            "sembol": pozisyon.sembol,
            "adet": pozisyon.adet,
            "ortalamaMaliyet": round(pozisyon.ortalama_maliyet, 2),
            "guncelFiyat": round(fiyat, 2),
            "guncelDeger": round(guncel_deger, 2),
            "karZarar": round(kar_zarar, 2),
            "karZararYuzde": round(kar_zarar_yuzde, 2),
            "fiyatGuncelMi": canli_fiyat is not None,
        })

    toplam_deger = kullanici.bakiye + toplam_pozisyon_degeri
    toplam_kar_zarar = toplam_deger - BASLANGIC_BAKIYESI
    toplam_kar_zarar_yuzde = (toplam_kar_zarar / BASLANGIC_BAKIYESI) * 100

    return {
        "bakiye": round(kullanici.bakiye, 2),
        "pozisyonlar": pozisyon_listesi,
        "toplamPozisyonDegeri": round(toplam_pozisyon_degeri, 2),
        "toplamPortfoyDegeri": round(toplam_deger, 2),
        "toplamKarZarar": round(toplam_kar_zarar, 2),
        "toplamKarZararYuzde": round(toplam_kar_zarar_yuzde, 2),
    }


def gecmis_kaydet(kullanici_id: int, toplam_deger: float, db: Session):
    db.add(PortfoyGecmisi(kullanici_id=kullanici_id, toplam_deger=toplam_deger))
    db.commit()


# ==========================================
# İSTEK MODELLERİ (Pydantic)
# ==========================================
class KayitIstek(BaseModel):
    kullanici_adi: str
    sifre: str


class GirisIstek(BaseModel):
    kullanici_adi: str
    sifre: str


class IslemIstek(BaseModel):
    sembol: str
    adet: float


# ==========================================
# ROTALAR: KİMLİK DOĞRULAMA
# ==========================================
@app.post("/kayit")
def kayit_ol(istek: KayitIstek, db: Session = Depends(db_al)):
    kullanici_adi = istek.kullanici_adi.strip().lower()
    if len(kullanici_adi) < 3:
        raise HTTPException(status_code=400, detail="Kullanıcı adı en az 3 karakter olmalı.")
    if len(istek.sifre) < 4:
        raise HTTPException(status_code=400, detail="Şifre en az 4 karakter olmalı.")

    mevcut = db.query(Kullanici).filter(Kullanici.kullanici_adi == kullanici_adi).first()
    if mevcut:
        raise HTTPException(status_code=400, detail="Bu kullanıcı adı zaten alınmış.")

    yeni_kullanici = Kullanici(
        kullanici_adi=kullanici_adi,
        sifre_hash=sifre_hashle(istek.sifre),
        bakiye=BASLANGIC_BAKIYESI,
    )
    db.add(yeni_kullanici)
    db.commit()
    db.refresh(yeni_kullanici)

    gecmis_kaydet(yeni_kullanici.id, BASLANGIC_BAKIYESI, db)

    token = token_uret(yeni_kullanici.id)
    return {"token": token, "kullaniciAdi": yeni_kullanici.kullanici_adi, "bakiye": yeni_kullanici.bakiye}


@app.post("/giris")
def giris_yap(istek: GirisIstek, db: Session = Depends(db_al)):
    kullanici_adi = istek.kullanici_adi.strip().lower()
    kullanici = db.query(Kullanici).filter(Kullanici.kullanici_adi == kullanici_adi).first()
    if not kullanici or not sifre_dogrula(istek.sifre, kullanici.sifre_hash):
        raise HTTPException(status_code=401, detail="Kullanıcı adı veya şifre hatalı.")

    token = token_uret(kullanici.id)
    return {"token": token, "kullaniciAdi": kullanici.kullanici_adi, "bakiye": kullanici.bakiye}


# ==========================================
# ROTALAR: PİYASA VERİLERİ (herkese açık, giriş gerektirmez)
# ==========================================
@app.get("/piyasa-durumu")
def piyasa_durumu_getir():
    acik, mesaj = piyasa_acik_mi()
    return {"acik": acik, "mesaj": mesaj}


@app.get("/piyasa")
def piyasa_verilerini_getir():
    try:
        tv_url = "https://scanner.tradingview.com/turkey/scan"
        body = {"columns": ["name", "close", "change", "volume"], "range": [0, 1000]}
        r = requests.post(tv_url, json=body, timeout=10)
        if r.status_code != 200:
            return {"hata": "TradingView yanıt vermedi"}

        data = r.json().get("data", [])
        tum_hisseler = []
        for item in data:
            d = item.get("d", [])
            if len(d) < 4:
                continue
            if d[1] is None or d[2] is None or d[3] is None:
                continue
            try:
                tum_hisseler.append({
                    "sembol": str(d[0]),
                    "fiyat": float(d[1]),
                    "degisimYuzdesi": float(d[2]),
                    "hacim": int(d[3]),
                })
            except (TypeError, ValueError):
                continue

        tum_hisseler = [h for h in tum_hisseler if h["fiyat"] > 0 and h["hacim"] > 0]

        return {
            "taranan": len(tum_hisseler),
            "yukselenler": sorted(tum_hisseler, key=lambda x: x["degisimYuzdesi"], reverse=True)[:10],
            "dusenler": sorted(tum_hisseler, key=lambda x: x["degisimYuzdesi"])[:10],
            "hacimliler": sorted(tum_hisseler, key=lambda x: x["hacim"], reverse=True)[:10],
        }
    except Exception as e:
        return {"hata": str(e)}


@app.get("/mumlar/{sembol}")
def mum_verisi_getir(sembol: str):
    sembol_saf = sembol.replace(".IS", "").upper()
    url = f"https://query2.finance.yahoo.com/v8/finance/chart/{sembol_saf}.IS?interval=1d&range=1mo"
    try:
        r = requests.get(url, headers={"User-Agent": "Mozilla/5.0"}, timeout=10)
        if r.status_code != 200:
            raise HTTPException(status_code=404, detail=f"'{sembol_saf}' için veri bulunamadı.")

        data = r.json()
        result = data.get("chart", {}).get("result")
        if not result:
            raise HTTPException(status_code=404, detail=f"'{sembol_saf}' için veri bulunamadı.")
        result = result[0]

        timestamps = result.get("timestamp", [])
        indicators = result.get("indicators", {}).get("quote", [])
        if not timestamps or not indicators:
            return []
        quote = indicators[0]

        closes = quote.get("close", [])
        opens = quote.get("open", [])
        highs = quote.get("high", [])
        lows = quote.get("low", [])
        volumes = quote.get("volume", [])

        mumlar = []
        son_gecerli_close = 0
        for i in range(len(timestamps)):
            c = closes[i] if i < len(closes) and closes[i] is not None else None
            o = opens[i] if i < len(opens) and opens[i] is not None else None
            h = highs[i] if i < len(highs) and highs[i] is not None else None
            l = lows[i] if i < len(lows) and lows[i] is not None else None
            v = volumes[i] if i < len(volumes) and volumes[i] is not None else 0.0

            if c is not None:
                son_gecerli_close = c
            elif son_gecerli_close != 0:
                c = o = h = l = son_gecerli_close
            else:
                continue

            mumlar.append({
                "timestamp": int(timestamps[i] * 1000),
                "open": o if o is not None else c,
                "high": h if h is not None else c,
                "low": l if l is not None else c,
                "close": c,
                "volume": v,
            })

        return mumlar
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ==========================================
# ROTALAR: FİYAT, PORTFÖY VE İŞLEMLER (giriş gerekli)
# ==========================================
@app.get("/fiyat/{sembol}")
def fiyat_getir(sembol: str, kullanici: Kullanici = Depends(gecerli_kullanici)):
    fiyat = guncel_fiyat_getir(sembol)
    if fiyat is None:
        raise HTTPException(status_code=404, detail=f"'{sembol}' için fiyat alınamadı.")
    return {"sembol": sembol.strip().upper().replace(".IS", ""), "fiyat": round(fiyat, 2)}


@app.get("/portfoy")
def portfoy_getir(kullanici: Kullanici = Depends(gecerli_kullanici), db: Session = Depends(db_al)):
    return portfoy_ozet_olustur(kullanici, db)


@app.post("/al")
def hisse_al(istek: IslemIstek, kullanici: Kullanici = Depends(gecerli_kullanici), db: Session = Depends(db_al)):
    acik, mesaj = piyasa_acik_mi()
    if not acik:
        raise HTTPException(status_code=400, detail=mesaj)

    if istek.adet <= 0:
        raise HTTPException(status_code=400, detail="Adet 0'dan büyük olmalı.")

    sembol = istek.sembol.strip().upper().replace(".IS", "")
    fiyat = guncel_fiyat_getir(sembol)
    if fiyat is None:
        raise HTTPException(status_code=404, detail=f"'{sembol}' için güncel fiyat alınamadı.")

    toplam_tutar = fiyat * istek.adet
    if toplam_tutar > kullanici.bakiye:
        raise HTTPException(status_code=400, detail="Yetersiz bakiye.")

    pozisyon = db.query(Pozisyon).filter(
        Pozisyon.kullanici_id == kullanici.id, Pozisyon.sembol == sembol
    ).first()

    if pozisyon:
        eski_toplam_maliyet = pozisyon.ortalama_maliyet * pozisyon.adet
        yeni_adet = pozisyon.adet + istek.adet
        pozisyon.ortalama_maliyet = (eski_toplam_maliyet + toplam_tutar) / yeni_adet
        pozisyon.adet = yeni_adet
    else:
        pozisyon = Pozisyon(kullanici_id=kullanici.id, sembol=sembol, adet=istek.adet, ortalama_maliyet=fiyat)
        db.add(pozisyon)

    kullanici.bakiye -= toplam_tutar
    db.add(Islem(kullanici_id=kullanici.id, sembol=sembol, tur="AL",
                 adet=istek.adet, fiyat=fiyat, toplam_tutar=toplam_tutar))
    db.commit()

    ozet = portfoy_ozet_olustur(kullanici, db)
    gecmis_kaydet(kullanici.id, ozet["toplamPortfoyDegeri"], db)
    return ozet


@app.post("/sat")
def hisse_sat(istek: IslemIstek, kullanici: Kullanici = Depends(gecerli_kullanici), db: Session = Depends(db_al)):
    acik, mesaj = piyasa_acik_mi()
    if not acik:
        raise HTTPException(status_code=400, detail=mesaj)

    if istek.adet <= 0:
        raise HTTPException(status_code=400, detail="Adet 0'dan büyük olmalı.")

    sembol = istek.sembol.strip().upper().replace(".IS", "")
    pozisyon = db.query(Pozisyon).filter(
        Pozisyon.kullanici_id == kullanici.id, Pozisyon.sembol == sembol
    ).first()

    if not pozisyon or pozisyon.adet < istek.adet:
        raise HTTPException(status_code=400, detail="Yeterli hisseniz yok.")

    fiyat = guncel_fiyat_getir(sembol)
    if fiyat is None:
        raise HTTPException(status_code=404, detail=f"'{sembol}' için güncel fiyat alınamadı.")

    toplam_tutar = fiyat * istek.adet
    pozisyon.adet -= istek.adet
    if pozisyon.adet <= 0.0001:
        db.delete(pozisyon)

    kullanici.bakiye += toplam_tutar
    db.add(Islem(kullanici_id=kullanici.id, sembol=sembol, tur="SAT",
                 adet=istek.adet, fiyat=fiyat, toplam_tutar=toplam_tutar))
    db.commit()

    ozet = portfoy_ozet_olustur(kullanici, db)
    gecmis_kaydet(kullanici.id, ozet["toplamPortfoyDegeri"], db)
    return ozet


@app.get("/islemler")
def islem_gecmisi(kullanici: Kullanici = Depends(gecerli_kullanici), db: Session = Depends(db_al)):
    kayitlar = db.query(Islem).filter(Islem.kullanici_id == kullanici.id).order_by(Islem.tarih.desc()).limit(200).all()
    return [{
        "sembol": k.sembol, "tur": k.tur, "adet": k.adet,
        "fiyat": round(k.fiyat, 2), "toplamTutar": round(k.toplam_tutar, 2),
        "tarih": k.tarih.isoformat(),
    } for k in kayitlar]


@app.get("/grafik")
def portfoy_grafigi(kullanici: Kullanici = Depends(gecerli_kullanici), db: Session = Depends(db_al)):
    kayitlar = db.query(PortfoyGecmisi).filter(
        PortfoyGecmisi.kullanici_id == kullanici.id
    ).order_by(PortfoyGecmisi.tarih.asc()).limit(500).all()
    return [{"tarih": k.tarih.isoformat(), "toplamDeger": round(k.toplam_deger, 2)} for k in kayitlar]


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
