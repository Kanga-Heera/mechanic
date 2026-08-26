import markdown
from xhtml2pdf import pisa

with open("RESULTS.md", encoding="utf-8") as f:
    md_text = f.read()

body_html = markdown.markdown(
    md_text,
    extensions=["tables", "fenced_code", "toc", "sane_lists"],
)

html = f"""<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<style>
    @page {{
        size: A4;
        margin: 2cm 1.6cm;
        @frame footer {{
            -pdf-frame-content: footerContent;
            bottom: 0.7cm;
            margin-left: 1.6cm;
            margin-right: 1.6cm;
            height: 1cm;
        }}
    }}
    body {{
        font-family: Helvetica, Arial, sans-serif;
        font-size: 9.5pt;
        line-height: 1.45;
        color: #1a1a1a;
    }}
    h1 {{
        font-size: 18pt;
        color: #111;
        border-bottom: 2px solid #333;
        padding-bottom: 6px;
        margin-top: 0;
    }}
    h2 {{
        font-size: 13.5pt;
        color: #111;
        border-bottom: 1px solid #999;
        padding-bottom: 3px;
        margin-top: 20px;
    }}
    h3 {{
        font-size: 11pt;
        color: #222;
        margin-top: 14px;
        margin-bottom: 4px;
    }}
    p {{
        margin: 4px 0;
    }}
    code {{
        font-family: Courier, monospace;
        font-size: 8.5pt;
        background-color: #f0f0f0;
        padding: 1px 3px;
    }}
    pre {{
        font-family: Courier, monospace;
        font-size: 8pt;
        background-color: #f5f5f5;
        border: 0.5px solid #ccc;
        padding: 6px;
        line-height: 1.3;
        white-space: pre-wrap;
    }}
    table {{
        border-collapse: collapse;
        width: 100%;
        margin: 8px 0;
        font-size: 7.5pt;
    }}
    th {{
        background-color: #333;
        color: #fff;
        padding: 4px 5px;
        text-align: left;
        font-size: 7.5pt;
    }}
    td {{
        border: 0.5px solid #bbb;
        padding: 3px 5px;
        vertical-align: top;
    }}
    tr:nth-child(even) td {{
        background-color: #f7f7f7;
    }}
    strong {{
        color: #000;
    }}
    hr {{
        border: none;
        border-top: 1px solid #ccc;
        margin: 16px 0;
    }}
    ul, ol {{
        margin: 4px 0;
        padding-left: 18px;
    }}
    li {{
        margin: 2px 0;
    }}
    a {{
        color: #1a5296;
    }}
</style>
</head>
<body>
<div id="footerContent" style="text-align:center; font-size:7.5pt; color:#888;">
    mechanic &mdash; detection rule maintenance triage: validation results &mdash; <pdf:pagenumber/> / <pdf:pagecount/>
</div>
{body_html}
</body>
</html>
"""

with open("results_render.html", "w", encoding="utf-8") as f:
    f.write(html)

with open("RESULTS.pdf", "wb") as pdf_file:
    result = pisa.CreatePDF(html, dest=pdf_file)

print("PDF generation error state:", result.err)
