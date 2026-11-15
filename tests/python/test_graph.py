from graph.investigate import EdgeObservation as E, investigate

def edge(a, at, b, bt, relation, time, roots=("raw-1",), device="host-1"):
    return E(a,at,b,bt,relation,device,time,.98,f"e-{time}-{b}",roots)

def test_time_bound_and_type_constraints():
    edges=[
       edge("p","Process","q","Process","SPAWNED",1000),
       edge("q","Process","n","NetworkEndpoint","CONNECTED_TO",2000,("raw-2",)),
       edge("q","Process","bad","NetworkEndpoint","CONNECTED_TO",500,("raw-3",)),
       edge("n","NetworkEndpoint","x","Process","SPAWNED",3000,("raw-4",)),
       edge("q","Process","remote","NetworkEndpoint","CONNECTED_TO",2100,("raw-5",),device="host-2")
    ]
    paths=investigate("p","host-1",edges,0,5000)
    assert any(len(p)==2 and p[-1].dst=="n" for p in paths)
    assert not any(p[-1].dst in ("bad","x","remote") for p in paths)

def test_bounded_and_no_evidence_no_paths():
    edges=[
       edge("p","Process","q","Process","SPAWNED",1000,()),
       edge("p","Process","s","Process","SPAWNED",1500,("root",))
    ]
    paths=investigate("p","host-1",edges,0,5000,max_edges=1)
    assert len(paths)<=1
    assert all(p[-1].dst!="q" for p in paths)
