from __future__ import annotations

import base64, io, json, math, textwrap
from pathlib import Path

import fitz
from PIL import Image as PILImage, ImageDraw
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import mm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import (
    BaseDocTemplate, Flowable, Frame, Image, NextPageTemplate, PageBreak,
    PageTemplate, Paragraph, Spacer, Table, TableStyle,
)

ROOT = Path(__file__).resolve().parents[1]
DATA = json.loads((ROOT / 'report' / 'report_data.json').read_text(encoding='utf-8'))
SOURCE = ROOT / 'Analisi Tecnica del Malware MyDoom.pdf'
OUTPUT = ROOT / 'MyDoom_Malware_Analysis_and_Detection_Report_v2.pdf'
BUILD = ROOT / '.report_build'
ASSETS = BUILD / 'assets'
PREVIEW = ROOT / 'report' / 'preview_contact_sheet.b64'
QA = ROOT / 'report' / 'qa.json'
W, H = A4
LEFT, RIGHT, TOP, BOTTOM = 18*mm, 18*mm, 20*mm, 18*mm
CW = W - LEFT - RIGHT
NAVY=colors.HexColor('#0B1220'); INK=colors.HexColor('#172033'); MUTED=colors.HexColor('#5E6B7C')
LINE=colors.HexColor('#DDE3EA'); GREEN=colors.HexColor('#22C55E'); GD=colors.HexColor('#0F7A39')
SOFT={'info':(colors.HexColor('#EEF4FA'),colors.HexColor('#2B6CB0')),
      'good':(colors.HexColor('#EAF8EF'),GD),'warn':(colors.HexColor('#FFF6DF'),colors.HexColor('#B7791F')),
      'danger':(colors.HexColor('#FDECEC'),colors.HexColor('#B42318'))}


def fonts():
    sets=[('/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf','/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf','/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf'),('/usr/share/fonts/truetype/liberation2/LiberationSans-Regular.ttf','/usr/share/fonts/truetype/liberation2/LiberationSans-Bold.ttf','/usr/share/fonts/truetype/liberation2/LiberationMono-Regular.ttf')]
    for a,b,c in sets:
        if all(Path(x).exists() for x in (a,b,c)):
            pdfmetrics.registerFont(TTFont('ReportSans',a)); pdfmetrics.registerFont(TTFont('ReportSansBold',b)); pdfmetrics.registerFont(TTFont('ReportMono',c))
            return 'ReportSans','ReportSansBold','ReportMono'
    return 'Helvetica','Helvetica-Bold','Courier'
F,FB,FM=fonts()
ST={
 'cover_k':ParagraphStyle('ck',fontName=FB,fontSize=10,leading=13,textColor=GREEN,spaceAfter=10),
 'cover_t':ParagraphStyle('ct',fontName=FB,fontSize=30,leading=34,textColor=colors.white,spaceAfter=10),
 'cover_s':ParagraphStyle('cs',fontName=F,fontSize=13,leading=18,textColor=colors.HexColor('#C7D2E0'),spaceAfter=16),
 'cover_m':ParagraphStyle('cm',fontName=F,fontSize=9.3,leading=14,textColor=colors.HexColor('#D4DCE7')),
 'h1':ParagraphStyle('h1',fontName=FB,fontSize=19,leading=23,textColor=NAVY,spaceBefore=5,spaceAfter=10,keepWithNext=True),
 'h2':ParagraphStyle('h2',fontName=FB,fontSize=13,leading=17,textColor=GD,spaceBefore=10,spaceAfter=6,keepWithNext=True),
 'body':ParagraphStyle('body',fontName=F,fontSize=9.35,leading=13.6,textColor=INK,spaceAfter=7,allowWidows=0,allowOrphans=0),
 'small':ParagraphStyle('small',fontName=F,fontSize=7.7,leading=10.4,textColor=MUTED,spaceAfter=4),
 'caption':ParagraphStyle('cap',fontName=F,fontSize=7.6,leading=10,textColor=MUTED,alignment=TA_CENTER,spaceBefore=3,spaceAfter=8),
 'table':ParagraphStyle('tab',fontName=F,fontSize=7.25,leading=9.3,textColor=INK),
 'table_b':ParagraphStyle('tabb',fontName=FB,fontSize=7.25,leading=9.3,textColor=INK),
 'call':ParagraphStyle('call',fontName=F,fontSize=8.9,leading=12.8,textColor=INK),
 'call_b':ParagraphStyle('callb',fontName=FB,fontSize=9,leading=12.8,textColor=INK),
 'ref':ParagraphStyle('ref',fontName=F,fontSize=7.25,leading=10,textColor=INK,spaceAfter=4),
 'toc':ParagraphStyle('toc',fontName=F,fontSize=9.5,leading=13,textColor=INK,leftIndent=8,spaceAfter=3),
}
def P(t,s='body'): return Paragraph(t,ST[s])

class Bar(Flowable):
    def __init__(self): super().__init__(); self.width=CW; self.height=2
    def draw(self): self.canv.setFillColor(GREEN); self.canv.rect(0,0,self.width,self.height,stroke=0,fill=1)

class Lifecycle(Flowable):
    def __init__(self): super().__init__(); self.width=CW; self.height=52*mm
    def draw(self):
        c=self.canv; labels=[('Delivery','Email attachment\nor P2P lure'),('Execution','User opens\nmalicious file'),('Persistence','Run key +\nCOM DLL'),('Propagation','SMTP fan-out\naddress harvesting'),('Backdoor','TCP proxy /\nsecondary payload'),('Impact','Variant-specific\nHTTP DDoS')]
        gap=4*mm; bw=(self.width-gap*(len(labels)-1))/len(labels); y=15*mm; bh=23*mm
        for i,(title,desc) in enumerate(labels):
            x=i*(bw+gap); c.setFillColor(colors.HexColor('#EEF4FA') if i%2==0 else colors.HexColor('#EAF8EF')); c.setStrokeColor(LINE); c.roundRect(x,y,bw,bh,4,stroke=1,fill=1)
            c.setFillColor(NAVY); c.setFont(FB,7.5); c.drawCentredString(x+bw/2,y+bh-8,title); c.setFillColor(INK); c.setFont(F,6.5)
            for j,line in enumerate(desc.split('\n')): c.drawCentredString(x+bw/2,y+bh-18-j*8,line)
            if i<len(labels)-1:
                ax=x+bw; ay=y+bh/2; c.setStrokeColor(GD); c.line(ax+1,ay,ax+gap-2,ay); c.line(ax+gap-5,ay+2.3,ax+gap-2,ay); c.line(ax+gap-5,ay-2.3,ax+gap-2,ay)
        c.setFont(F,7); c.setFillColor(MUTED); c.drawString(0,4,'Figure 1 - Analyst reconstruction of the MyDoom family behavior chain. Variant behavior differs.')


def callout(title,text,kind):
    bg,edge=SOFT[kind]; t=Table([[P(title,'call_b')],[P(text,'call')]],colWidths=[CW-10*mm],hAlign='LEFT')
    t.setStyle(TableStyle([('BACKGROUND',(0,0),(-1,-1),bg),('BOX',(0,0),(-1,-1),.8,edge),('LEFTPADDING',(0,0),(-1,-1),7),('RIGHTPADDING',(0,0),(-1,-1),7),('TOPPADDING',(0,0),(-1,-1),6),('BOTTOMPADDING',(0,0),(-1,-1),6)])); return t

def table(rows,widths):
    data=[[P(x,'table_b' if r==0 else 'table') for x in row] for r,row in enumerate(rows)]
    t=Table(data,colWidths=[x*mm for x in widths],repeatRows=1,hAlign='LEFT')
    t.setStyle(TableStyle([('VALIGN',(0,0),(-1,-1),'TOP'),('GRID',(0,0),(-1,-1),.35,LINE),('BACKGROUND',(0,0),(-1,0),colors.HexColor('#EAF0F6')),('LINEBELOW',(0,0),(-1,0),1,GD),('LEFTPADDING',(0,0),(-1,-1),4),('RIGHTPADDING',(0,0),(-1,-1),4),('TOPPADDING',(0,0),(-1,-1),4),('BOTTOMPADDING',(0,0),(-1,-1),4)])); return t

def source_images():
    ASSETS.mkdir(parents=True,exist_ok=True); doc=fitz.open(SOURCE); pages={2:1,5:1,6:2,7:1,9:2,11:3,14:1}; out={}
    for pno,count in pages.items():
        imgs=doc[pno-1].get_images(full=True)
        for i,img in enumerate(imgs[:count]):
            info=doc.extract_image(img[0]); key=f'p{pno}_{i+1}'; path=ASSETS/f"{key}.{info.get('ext','png')}"; path.write_bytes(info['image']); out[key]=path
    return out

def figure(path,caption,max_h):
    if not path or not path.exists(): return []
    with PILImage.open(path) as im: w,h=im.size
    scale=min(CW/w,(max_h*mm)/h); return [Spacer(1,3*mm),Image(str(path),width=w*scale,height=h*scale,hAlign='CENTER'),P(f'Figure - {caption}','caption')]

def cover(c,doc):
    c.saveState(); c.setFillColor(NAVY); c.rect(0,0,W,H,fill=1,stroke=0); c.setStrokeColor(colors.HexColor('#17324B')); c.setLineWidth(.5)
    for x in range(0,int(W),22): c.line(x,0,x,H)
    for y in range(0,int(H),22): c.line(0,y,W,y)
    c.setFillColor(GREEN); c.rect(0,H-5*mm,W,5*mm,fill=1,stroke=0); c.restoreState()

def body_page(c,doc):
    c.saveState(); c.setStrokeColor(LINE); c.line(LEFT,H-13*mm,W-RIGHT,H-13*mm); c.setFont(FB,7.5); c.setFillColor(NAVY); c.drawString(LEFT,H-10.5*mm,'MYDOOM - MALWARE ANALYSIS & DETECTION ENGINEERING'); c.setFont(FB,8); c.drawRightString(W-RIGHT,H-10.5*mm,'TLP:CLEAR'); c.line(LEFT,12*mm,W-RIGHT,12*mm); c.setFont(F,7); c.setFillColor(MUTED); c.drawString(LEFT,8*mm,'Michel Di Vincenzo | Defensive research report v2.0'); c.drawRightString(W-RIGHT,8*mm,f'Page {doc.page}'); c.restoreState()

class Doc(BaseDocTemplate):
    def __init__(self,path):
        super().__init__(path,pagesize=A4,leftMargin=LEFT,rightMargin=RIGHT,topMargin=TOP,bottomMargin=BOTTOM,title='MyDoom Malware Analysis and Detection Report',author=DATA['author'])
        fc=Frame(LEFT,BOTTOM,CW,H-TOP-BOTTOM,id='cover',leftPadding=0,rightPadding=0,topPadding=0,bottomPadding=0); fb=Frame(LEFT,BOTTOM+4*mm,CW,H-TOP-BOTTOM-2*mm,id='body',leftPadding=0,rightPadding=0,topPadding=0,bottomPadding=0)
        self.addPageTemplates([PageTemplate(id='Cover',frames=[fc],onPage=cover),PageTemplate(id='Body',frames=[fb],onPage=body_page)])

def story(figs):
    s=[Spacer(1,40*mm),P('MALWARE ANALYSIS / DETECTION ENGINEERING','cover_k'),P(DATA['title'],'cover_t'),P(DATA['subtitle'],'cover_s'),Spacer(1,9*mm)]
    meta=[[P('Classification','cover_m'),P(DATA['classification'],'cover_m')],[P('Report version','cover_m'),P(f"{DATA['version']} - {DATA['date']}",'cover_m')],[P('Author','cover_m'),P(DATA['author'],'cover_m')],[P('Scope','cover_m'),P('Defensive malware research and detection engineering','cover_m')]]
    mt=Table(meta,colWidths=[38*mm,90*mm]); mt.setStyle(TableStyle([('BACKGROUND',(0,0),(-1,-1),colors.HexColor('#101D2E')),('BOX',(0,0),(-1,-1),.8,colors.HexColor('#2C3F52')),('INNERGRID',(0,0),(-1,-1),.35,colors.HexColor('#2C3F52')),('LEFTPADDING',(0,0),(-1,-1),7),('RIGHTPADDING',(0,0),(-1,-1),7),('TOPPADDING',(0,0),(-1,-1),6),('BOTTOMPADDING',(0,0),(-1,-1),6)])); s += [mt,Spacer(1,18*mm),P('This edition separates verified sample identifiers, family-wide historical behavior and analyst-derived mappings. It intentionally avoids reproducing malware code or operational exploitation instructions.','cover_m'),NextPageTemplate('Body'),PageBreak()]
    toc=[f"{x['number']}. {x['title']}" for x in DATA['sections']]
    for sec in DATA['sections']:
        s += [Spacer(1,2*mm),P(f"{sec['number']}. {sec['title']}",'h1'),Bar()]
        for item in sec['items']:
            typ=item['type']
            if typ=='p': s.append(P(item['text']))
            elif typ=='small': s.append(P(item['text'],'small'))
            elif typ=='h2': s.append(P(item['text'],'h2'))
            elif typ=='callout': s.append(callout(item['title'],item['text'],item['kind']))
            elif typ=='table': s.append(table(item['rows'],item['widths']))
            elif typ=='diagram': s.append(Lifecycle())
            elif typ=='figure': s += figure(figs.get(item['key']),item['caption'],item.get('max_h',80))
            elif typ=='contents': s += [P(x,'toc') for x in toc]
            elif typ=='references': s += [P(x,'ref') for x in DATA['references']]
        s.append(Spacer(1,2*mm))
    s += [Spacer(1,6*mm),P('End of report - TLP:CLEAR','small')]
    return s

def contact(pdf):
    doc=fitz.open(pdf); thumbs=[]
    for i,p in enumerate(doc):
        pix=p.get_pixmap(matrix=fitz.Matrix(.34,.34),alpha=False); im=PILImage.frombytes('RGB',[pix.width,pix.height],pix.samples); im.thumbnail((220,310)); c=PILImage.new('RGB',(230,330),'white'); c.paste(im,((230-im.width)//2,5)); ImageDraw.Draw(c).text((8,314),f'p{i+1}',fill='black'); thumbs.append(c)
    cols=4; rows=math.ceil(len(thumbs)/cols); sh=PILImage.new('RGB',(cols*230,rows*330),'#D9DEE5')
    for i,im in enumerate(thumbs): sh.paste(im,((i%cols)*230,(i//cols)*330))
    b=io.BytesIO(); sh.save(b,format='JPEG',quality=46,optimize=True); enc=base64.b64encode(b.getvalue()).decode('ascii'); PREVIEW.write_text(textwrap.fill(enc,4000)+'\n',encoding='ascii'); return len(b.getvalue())

def qa(pdf):
    doc=fitz.open(pdf); pages=[]; issues=[]
    for i,p in enumerate(doc):
        txt=p.get_text('text'); pages.append({'page':i+1,'text_chars':len(txt),'blocks':len(p.get_text('blocks'))})
        if i>0 and len(txt.strip())<45: issues.append(f'page {i+1}: unusually little text')
    result={'file':pdf.name,'size_bytes':pdf.stat().st_size,'page_count':doc.page_count,'pages':pages,'issues':issues,'contact_sheet_bytes':contact(pdf),'status':'pass' if not issues else 'review'}; QA.write_text(json.dumps(result,indent=2),encoding='utf-8'); return result

def main():
    if not SOURCE.exists(): raise SystemExit(f'missing source PDF: {SOURCE}')
    BUILD.mkdir(exist_ok=True); figs=source_images(); Doc(str(OUTPUT)).build(story(figs)); result=qa(OUTPUT); print(json.dumps(result,indent=2)); return 0
if __name__=='__main__': raise SystemExit(main())
