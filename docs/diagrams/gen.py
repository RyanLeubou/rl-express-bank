import json, subprocess, html, uuid, re
from xml.sax.saxutils import quoteattr

FONT = 14
STYLES = {
 'box':   'rounded=1;whiteSpace=wrap;html=1;fillColor=#dae8fc;strokeColor=#6c8ebf;fontSize=14;',
 'db':    'shape=cylinder3;whiteSpace=wrap;html=1;boundedLbl=1;backgroundOutline=1;size=12;fillColor=#fff2cc;strokeColor=#d6b656;fontSize=14;',
 'file':  'shape=parallelogram;perimeter=parallelogramPerimeter;whiteSpace=wrap;html=1;fixedSize=1;fillColor=#fff2cc;strokeColor=#d6b656;fontSize=14;',
 'dec':   'rhombus;whiteSpace=wrap;html=1;fillColor=#ffe6cc;strokeColor=#d79b00;fontSize=14;',
 'ok':    'rounded=1;whiteSpace=wrap;html=1;fillColor=#d5e8d4;strokeColor=#82b366;fontSize=14;',
 'bad':   'rounded=1;whiteSpace=wrap;html=1;fillColor=#f8cecc;strokeColor=#b85450;fontSize=14;',
 'ai':    'rounded=1;whiteSpace=wrap;html=1;fillColor=#e1d5e7;strokeColor=#9673a6;fontSize=14;',
 'grey':  'rounded=1;whiteSpace=wrap;html=1;fillColor=#f5f5f5;strokeColor=#666666;fontSize=14;',
 'entity':'rounded=0;whiteSpace=wrap;html=1;fillColor=#dae8fc;strokeColor=#6c8ebf;fontSize=13;fontStyle=1;',
}
CLUSTER = 'rounded=1;whiteSpace=wrap;html=1;dashed=1;fillColor=#F7F9FC;strokeColor=#7F8C9A;verticalAlign=top;align=left;spacingLeft=12;spacingTop=6;fontStyle=1;fontSize=15;container=1;collapsible=0;'
EDGE = 'html=1;curved=1;endArrow=block;endFill=1;strokeColor=#4D4D4D;fontSize=12;labelBackgroundColor=#FFFFFF;'

def lab(t):
    return '<br>'.join(html.escape(p, quote=False) for p in t.split('\n'))

def size(t, kind):
    lines = t.split('\n'); m = max(len(l) for l in lines)
    w = max(170, int(m*7.6)+44); h = max(58, 26+20*len(lines))
    if kind=='dec': w, h = int(w*1.35), int(h*1.6)
    if kind=='db': h += 20
    return w, h

class Page:
    def __init__(self, name):
        self.name=name; self.cells=[]; self.n=2
    def nid(self):
        self.n+=1; return f'c{self.n}'
    def vertex(self, value, style, x,y,w,h, parent='1', cid=None):
        cid = cid or self.nid()
        self.cells.append(f'<mxCell id="{cid}" value={quoteattr(value)} style="{style}" vertex="1" parent="{parent}"><mxGeometry x="{x:.0f}" y="{y:.0f}" width="{w:.0f}" height="{h:.0f}" as="geometry"/></mxCell>')
        return cid
    def edge(self, value, style, src=None, dst=None, pts=None, sp=None, tp=None):
        cid=self.nid(); a=''
        if src: a+=f' source="{src}"'
        if dst: a+=f' target="{dst}"'
        g='<mxGeometry relative="1" as="geometry">'
        if sp: g+=f'<mxPoint x="{sp[0]:.0f}" y="{sp[1]:.0f}" as="sourcePoint"/>'
        if tp: g+=f'<mxPoint x="{tp[0]:.0f}" y="{tp[1]:.0f}" as="targetPoint"/>'
        if pts: g+='<Array as="points">'+''.join(f'<mxPoint x="{x:.0f}" y="{y:.0f}"/>' for x,y in pts)+'</Array>'
        g+='</mxGeometry>'
        self.cells.append(f'<mxCell id="{cid}" value={quoteattr(value)} style="{style}" edge="1" parent="1"{a}>{g}</mxCell>')
    def xml(self):
        return (f'<diagram id="{uuid.uuid4().hex[:12]}" name={quoteattr(self.name)}><mxGraphModel dx="1400" dy="900" grid="1" gridSize="10" guides="1" tooltips="1" connect="1" arrows="1" fold="1" page="0" pageScale="1" pageWidth="1600" pageHeight="1200" math="0" shadow="0"><root><mxCell id="0"/><mxCell id="1" parent="0"/>'
                + ''.join(self.cells) + '</root></mxGraphModel></diagram>')

def flow(name, rankdir, nodes, edges, clusters=(), title=None, ranksep=0.9, nodesep=0.55, er=False):
    """nodes: id -> (label, kind); edges: (a,b,label[,style]); clusters: (cid,label,[ids])"""
    p = Page(name)
    dims = {k: size(v[0], v[1]) for k,v in nodes.items()}
    in_cl = {}
    dot = [f'digraph G {{ rankdir={rankdir}; ranksep={ranksep}; nodesep={nodesep}; splines=spline; compound=true;',
           'node [shape=box, fixedsize=true, fontsize=14]; graph [fontsize=15];']
    for cid,cl,ids in clusters:
        dot.append(f'subgraph cluster_{cid} {{ label="{cl}"; margin=24;')
        for i in ids:
            w,h=dims[i]; dot.append(f'"{i}" [width={w/72:.3f}, height={h/72:.3f}];'); in_cl[i]=cid
        dot.append('}')
    for k in nodes:
        if k not in in_cl:
            w,h=dims[k]; dot.append(f'"{k}" [width={w/72:.3f}, height={h/72:.3f}];')
    for e in edges:
        l = e[2] if len(e)>2 else ''
        extra = f', label="{" "*min(len(l),30)}"' if l else ''
        dot.append(f'"{e[0]}" -> "{e[1]}" [fontsize=12{extra}];')
    dot.append('}')
    out = subprocess.run(['dot','-Tjson'], input='\n'.join(dot), capture_output=True, text=True, check=True).stdout
    g = json.loads(out)
    H = float(g['bb'].split(',')[3]); off=(40, 70)
    T = lambda x,y: (x+off[0], H-y+off[1])
    if title:
        p.vertex(lab(title), 'text;html=1;fontSize=20;fontStyle=1;align=left;verticalAlign=middle;', 40, 10, 1000, 40)
    ids={}; cl_origin={}
    for o in g.get('objects', []):
        if o['name'].startswith('cluster_') and 'bb' in o:
            x0,y0,x1,y1 = map(float, o['bb'].split(','))
            X,Y = T(x0,y1); w,h = x1-x0, y1-y0
            cid = o['name'][8:]; label = [c for c in clusters if c[0]==cid][0][1]
            ids['cl_'+cid] = p.vertex(lab(label), CLUSTER, X, Y, w, h); cl_origin[cid]=(X,Y)
    for o in g.get('objects', []):
        if o['name'] in nodes:
            k=o['name']; x,y=map(float,o['pos'].split(',')); w,h=dims[k]; X,Y=T(x,y); X-=w/2; Y-=h/2
            parent='1'
            if k in in_cl:
                ox,oy=cl_origin[in_cl[k]]; X-=ox; Y-=oy; parent=ids['cl_'+in_cl[k]]
            ids[k]=p.vertex(lab(nodes[k][0]), STYLES[nodes[k][1]], X,Y,w,h, parent=parent)
    name_of = {o['_gvid']:o['name'] for o in g.get('objects',[])}
    for i,ed in enumerate(g.get('edges', [])):
        e = edges[i]; a,b = name_of[ed['tail']], name_of[ed['head']]
        pts=[]
        raw = [t for t in ed.get('pos','').split(' ') if t and not t.startswith(('e,','s,'))]
        cp=[tuple(map(float,t.split(','))) for t in raw]
        on=[cp[j] for j in range(0,len(cp),3)]
        if len(on)>2: pts=[T(*q) for q in on[1:-1]]
        style = EDGE + (e[3] if len(e)>3 else '')
        p.edge(lab(e[2]) if len(e)>2 and e[2] else '', style, ids[a], ids[b], pts)
    return p

# ---------- sequence diagrams ----------
def wrap(t, n):
    words=t.split(' '); lines=[]; cur=''
    for w in words:
        if len(cur)+len(w)+1>n and cur: lines.append(cur); cur=w
        else: cur=(cur+' '+w).strip()
    lines.append(cur); return '\n'.join(lines)

def seq(name, parts, steps, title=None, gap=270):
    p=Page(name); x0=60; top=80 if title else 40
    if title: p.vertex(lab(title),'text;html=1;fontSize=20;fontStyle=1;align=left;',40,10,1200,40)
    xs={pid: x0+i*gap+110 for i,(pid,_,_) in enumerate(parts)}
    y=top+110; frames=[]; drawn=[]; notes=[]
    def rng():
        return x0-20, x0+(len(parts)-1)*gap+240
    for s in steps:
        k=s[0]
        if k in ('m','r'):
            _,a,b,t=s
            if a==b:
                x=xs[a]; txt=wrap(t,34)
                p.edge(lab(txt),'html=1;endArrow=block;endFill=1;strokeColor=#4D4D4D;fontSize=12;align=left;labelBackgroundColor=#FFFFFF;'+('dashed=1;' if k=='r' else ''), sp=(x,y), tp=(x,y+26), pts=[(x+60,y),(x+60,y+26)])
                y+=62; continue
            xa,xb=xs[a],xs[b]; n=max(24,int(abs(xb-xa)/7.2)); txt=wrap(t,n); lines=txt.count('\n')+1
            y+= 16*(lines-1)
            p.edge(lab(txt),'html=1;endArrow=block;endFill=1;strokeColor=#4D4D4D;fontSize=12;verticalAlign=bottom;labelBackgroundColor=none;'+('dashed=1;' if k=='r' else ''), sp=(xa,y), tp=(xb,y))
            y+=52
        elif k=='note':
            _,a,b,t=s; xa,xb=sorted([xs[a],xs[b]]); w=max(260,xb-xa+200); txt=wrap(t,int(w/7.4)); h=26+18*(txt.count('\n')+1)
            p.vertex(lab(txt),'shape=note;whiteSpace=wrap;html=1;size=14;fillColor=#fff2cc;strokeColor=#d6b656;fontSize=13;',(xa+xb)/2-w/2,y-10,w,h)
            y+=h+20
        elif k=='alt':
            frames.append({'y':y,'labels':[(s[1],y)],'kw':s[2] if len(s)>2 else 'alt'}); y+=40
        elif k=='else':
            frames[-1]['labels'].append((s[1],y)); y+=40
        elif k=='end':
            f=frames.pop(); d=len(frames); L,R=rng(); L+=d*14; R-=d*14; y+=6
            drawn.append((f,L,R,y)); y+=24
    bottom=y+30
    for f,L,R,yend in drawn:
        p.vertex(lab(f['kw']),f'shape=umlFrame;whiteSpace=wrap;html=1;width=70;height=26;fillColor=none;strokeColor=#9673a6;fontStyle=1;fontSize=13;',L,f['y']-8,R-L,yend-f['y']+8)
        for i,(t,ly) in enumerate(f['labels']):
            if i>0: p.edge('', 'endArrow=none;dashed=1;html=1;strokeColor=#9673a6;', sp=(L,ly-8), tp=(R,ly-8))
            p.vertex(lab('['+t+']'),'text;html=1;fontSize=13;fontStyle=2;fontColor=#6A3D8A;align=left;',L+(80 if i==0 else 10),ly-6,600,24)
    for pid,label,kind in parts:
        st=('shape=umlLifeline;participant=umlActor;' if kind=='actor' else 'shape=umlLifeline;')+'perimeter=lifelinePerimeter;whiteSpace=wrap;html=1;container=0;collapsible=0;recursiveResize=0;outlineConnect=0;size=60;fontSize=14;fillColor=#dae8fc;strokeColor=#6c8ebf;'
        if kind=='actor': st+='verticalLabelPosition=bottom;verticalAlign=top;'
        cw=40 if kind=='actor' else 200
        # lifelines first (z-order under messages)
        p.cells.insert(0, f'<mxCell id="ll_{pid}" value={quoteattr(lab(label))} style="{st}" vertex="1" parent="1"><mxGeometry x="{xs[pid]-cw/2:.0f}" y="{top}" width="{cw}" height="{bottom-top:.0f}" as="geometry"/></mxCell>')
    return p
