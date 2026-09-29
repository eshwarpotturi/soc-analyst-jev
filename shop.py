"""A small, deliberately simple storefront ("ByteBazaar") served by the target app.

It stands in for a quickly built, vibe-coded web app: a search box, a login form
and invoice downloads. Browse it THROUGH the proxy (http://127.0.0.1:8080/shop)
and every page load, search and login is judged by Jev first.

Output is HTML-escaped: this page is the thing being protected, not a vulnerable lab.
"""
from html import escape
from urllib.parse import parse_qs

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse

router = APIRouter(prefix="/shop")

PRODUCTS = [
    ("Trail Running Shoes", 4299, "Grippy soles for wet mornings."),
    ("Mechanical Keyboard", 6499, "Tactile switches, hot-swappable keys."),
    ("Noise-Cancelling Headphones", 8999, "Thirty hours of battery."),
    ("Steel Water Bottle", 899, "Keeps chai hot for twelve hours."),
    ("Canvas Backpack", 2499, "Fits a 15-inch laptop."),
    ("Desk Lamp", 1599, "Warm light, three brightness levels."),
]
FILES = ["invoice_2026.pdf", "warranty_card.pdf", "order_history.csv"]
DEMO_USER, DEMO_PASSWORD = "admin", "admin"

CSS = """
:root{--bg:#f6f3ee;--card:#fff;--ink:#23201c;--dim:#7a7268;--line:#e4ddd2;--brand:#d9480f;--ok:#2b8a3e;--bad:#c92a2a}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);font:15px/1.5 system-ui,-apple-system,"Segoe UI",sans-serif}
header{display:flex;flex-wrap:wrap;gap:12px;align-items:center;justify-content:space-between;padding:14px 20px;background:var(--card);border-bottom:1px solid var(--line)}
header a{color:var(--ink);text-decoration:none;font-weight:700;font-size:20px}
header a span{color:var(--brand)}
form.search{display:flex;gap:6px;flex:1;max-width:460px;min-width:220px}
input{font:inherit;padding:8px 10px;border:1px solid var(--line);border-radius:6px;background:#fff;min-width:0;flex:1}
button{font:inherit;padding:8px 14px;border:0;border-radius:6px;background:var(--brand);color:#fff;cursor:pointer}
main{max-width:980px;margin:0 auto;padding:20px}
h1{font-size:22px;margin:0 0 14px}
h2{font-size:16px;margin:0 0 10px}
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(200px,1fr));gap:12px}
.card{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:14px}
.price{font-weight:700;color:var(--brand)}
.muted{color:var(--dim);font-size:13px}
.row{display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:12px;margin-top:18px}
.login{display:flex;flex-direction:column;gap:8px}
.ok{color:var(--ok);font-weight:600}.bad{color:var(--bad);font-weight:600}
ul{margin:0;padding-left:18px}
a{color:var(--brand)}
"""


def page(title: str, body: str, status: int = 200) -> HTMLResponse:
    html = f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1"><title>{escape(title)} · ByteBazaar</title>
<style>{CSS}</style></head><body>
<header><a href="/shop">Byte<span>Bazaar</span></a>
<form class="search" action="/shop/search" method="get"><input name="q" placeholder="Search products" aria-label="Search products"><button>Search</button></form>
</header><main>{body}</main></body></html>"""
    return HTMLResponse(html, status_code=status)


def product_cards(items) -> str:
    return "".join(
        f'<div class="card"><h2>{escape(n)}</h2><div class="price">&#8377;{p:,}</div><div class="muted">{escape(d)}</div></div>'
        for n, p, d in items
    )


@router.get("", response_class=HTMLResponse)
def home():
    files = "".join(f'<li><a href="/shop/files?name={escape(f)}">{escape(f)}</a></li>' for f in FILES)
    body = f"""<h1>Today's picks</h1><div class="grid">{product_cards(PRODUCTS)}</div>
<div class="row">
  <div class="card"><h2>Sign in</h2>
    <form class="login" action="/shop/login" method="post">
      <input name="username" placeholder="Username" aria-label="Username" autocomplete="username">
      <input name="password" type="password" placeholder="Password" aria-label="Password" autocomplete="current-password">
      <button>Sign in</button>
    </form><p class="muted">Demo account: admin / admin</p></div>
  <div class="card"><h2>Your documents</h2><ul>{files}</ul></div>
</div>"""
    return page("Shop", body)


@router.get("/search", response_class=HTMLResponse)
def search(q: str = ""):
    hits = [p for p in PRODUCTS if q.lower() in p[0].lower()] if q else PRODUCTS
    results = f'<div class="grid">{product_cards(hits)}</div>' if hits else '<p class="muted">No products match.</p>'
    return page("Search", f"<h1>Results for &ldquo;{escape(q)}&rdquo;</h1>{results}")


@router.post("/login", response_class=HTMLResponse)
async def login(request: Request):
    form = parse_qs((await request.body()).decode("utf-8", errors="replace"))
    user = form.get("username", [""])[0]
    pw = form.get("password", [""])[0]
    if user == DEMO_USER and pw == DEMO_PASSWORD:
        return page("Signed in", f'<h1 class="ok">Welcome back, {escape(user)}</h1><p><a href="/shop">Continue shopping</a></p>')
    return page("Sign in failed", '<h1 class="bad">Wrong username or password</h1><p><a href="/shop">Try again</a></p>', 401)


@router.get("/files", response_class=HTMLResponse)
def files(name: str = ""):
    if name in FILES:
        return page("Download", f"<h1>Downloading {escape(name)}</h1><p class=\"muted\">(Demo only: no real file.)</p><p><a href=\"/shop\">Back to shop</a></p>")
    return page("Not found", f"<h1 class=\"bad\">File not found</h1><p class=\"muted\">{escape(name)}</p><p><a href=\"/shop\">Back to shop</a></p>", 404)
