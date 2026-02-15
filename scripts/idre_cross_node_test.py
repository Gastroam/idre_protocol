import json, time, urllib.request

NODE_A='http://127.0.0.1:8820'
NODE_B='http://127.0.0.1:8821'

def post(url, payload, timeout=60):
    data=json.dumps(payload).encode('utf-8')
    req=urllib.request.Request(url, data=data, headers={'Content-Type':'application/json'}, method='POST')
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.getcode(), json.loads(r.read().decode('utf-8'))

state={'seed':7245,'plane_id':'covenant','tau':0.7,'epoch':2,'state_digest':'53'*32}
indices=[i & 0xFF for i in range(256)]
encode_ctx={'session_id':'aa'*16,'sender_id':'bb'*16,'counter':1,'private_key_seed':'alice'}

send_code, send_body = post(NODE_A+'/api/idre/send', {'state':state,'semantic_indices':indices,'encode_ctx':encode_ctx}, timeout=120)
packet_b64 = send_body.get('packet_b64')
pub_hex = send_body.get('public_key_hex')

decode_ctx={
  'trust_store': {'bb'*16: pub_hex},
  'expected_session_id': 'aa'*16,
  'expected_sender_id': 'bb'*16,
  'expected_indices': indices,
}
recv_code, recv_body = post(NODE_B+'/api/idre/receive', {'state':state,'packet_b64':packet_b64,'decode_ctx':decode_ctx}, timeout=120)
replay_code, replay_body = post(NODE_B+'/api/idre/receive', {'state':state,'packet_b64':packet_b64,'decode_ctx':decode_ctx}, timeout=120)

report={
  'ts': time.strftime('%Y-%m-%dT%H:%M:%S'),
  'node_a': NODE_A,
  'node_b': NODE_B,
  'send': {'code': send_code, 'body': send_body},
  'receive': {'code': recv_code, 'body': recv_body},
  'replay': {'code': replay_code, 'body': replay_body},
}

out_path='logs/idre_cross_node_test_{}.json'.format(int(time.time()))
with open(out_path,'w',encoding='utf-8') as f:
    json.dump(report,f,indent=2)

print('WROTE', out_path)
print('SEND_OK', send_code==200 and send_body.get('status')=='ok')
print('RECV_STATUS', recv_body.get('decode_status'))
print('REPLAY_STATUS', replay_body.get('decode_status'))
