import {readFile} from 'node:fs/promises';
import {spawn} from 'node:child_process';
import {X509Certificate,createPrivateKey} from 'node:crypto';
import {createSecureContext} from 'node:tls';

function unpack(pfx,password,args,binary='openssl'){
 return new Promise((resolve,reject)=>{
  // No Windows o OpenSSL não herda fd:3 do runtime C. A senha vai somente
  // no ambiente do processo filho, nunca em argumentos, arquivos ou ambiente global.
  const windows=process.platform==='win32';
  const child=spawn(binary,['pkcs12',...args,'-passin',windows?'env:ROYAL_CERT_PASSWORD':'fd:3'],{
   stdio:windows?['pipe','pipe','ignore']:['pipe','pipe','ignore','pipe'],
   ...(windows?{env:{...process.env,ROYAL_CERT_PASSWORD:password}}:{}),windowsHide:true
  });
  const output=[];let size=0,finished=false;
  const done=(error,value)=>{if(finished)return;finished=true;clearTimeout(timer);error?reject(error):resolve(value);};
  const timer=setTimeout(()=>{child.kill();done(Error('Não foi possível ler o certificado.'));},7000);
  child.on('error',()=>done(Error('O computador precisa do OpenSSL.')));
  child.stdout.on('data',b=>{size+=b.length;if(size>2*1024*1024){child.kill();done(Error('Certificado excede o limite.'));}else output.push(b);});
  child.on('close',code=>done(code===0?null:Error('Não foi possível abrir o certificado com a senha configurada.'),Buffer.concat(output)));
  child.stdin.on('error',()=>{});
  if(!windows){child.stdio[3].on('error',()=>{});child.stdio[3].end(password+'\n');}
  child.stdin.end(pfx);
 });
}
// Parser DER limitado à extensão otherName de CNPJ (ICP-Brasil 2.16.76.1.3.3).
function parseDer(buf,start=0,end=buf.length,depth=0){if(depth>24)throw Error('Certificado inválido.');const nodes=[];while(start<end){const tag=buf[start++];if(start>=end)throw Error('Certificado inválido.');let length=buf[start++];if(length&128){const count=length&127;if(count<1||count>4||start+count>end)throw Error('Certificado inválido.');length=0;for(let i=0;i<count;i++)length=length*256+buf[start++];}if(start+length>end)throw Error('Certificado inválido.');const value=buf.subarray(start,start+length);nodes.push({tag,value,children:tag&32?parseDer(buf,start,start+length,depth+1):[]});start+=length;}return nodes;}
export function certificateCnpj(der){const oid=Buffer.from([0x60,0x4c,0x01,0x03,0x03]),matches=new Set();const values=node=>{if([4,12,19,22].includes(node.tag)){const text=node.value.toString('utf8');if(/^\d{14}$/.test(text))matches.add(text);}for(const c of node.children)values(c);};const walk=(nodes,depth=0)=>{if(depth>30)throw Error('Certificado inválido.');for(const n of nodes){if(n.children.some(c=>c.tag===6&&c.value.equals(oid)))for(const c of n.children)if(c.tag!==6)values(c);if(n.tag===4&&n.value[0]===0x30){try{walk(parseDer(n.value),depth+1);}catch{/* Outra extensão, sem CNPJ. */}}walk(n.children,depth+1);}};walk(parseDer(der));if(matches.size!==1)throw Error('Não foi possível identificar um único CNPJ na extensão ICP-Brasil do certificado.');return [...matches][0];}
export async function loadCertificate(env,expectedCnpj){
 if(!env.NFSE_PFX_FILE&&!env.NFSE_PFX_BASE64&&!env.NFSE_PFX_BASE64_FILE)return null;
 const pfx=env.NFSE_PFX_FILE?await readFile(env.NFSE_PFX_FILE):Buffer.from(env.NFSE_PFX_BASE64_FILE?await readFile(env.NFSE_PFX_BASE64_FILE,'utf8'):env.NFSE_PFX_BASE64,'base64');
 const password=env.NFSE_PFX_PASSWORD_FILE?(await readFile(env.NFSE_PFX_PASSWORD_FILE,'utf8')).replace(/\r?\n$/,''):env.NFSE_PFX_PASSWORD;
 if(!pfx.length||pfx.length>1024*1024||typeof password!=='string'||password.length>1024||/[\r\n]/.test(password))throw Error('Confira o arquivo e a senha privados do certificado.');
 let certPem,keyPem;
 try{for(const legacy of[false,true]){try{const flags=legacy?['-legacy']:[];certPem=await unpack(pfx,password,[...flags,'-nokeys'],env.OPENSSL_BIN);keyPem=await unpack(pfx,password,[...flags,'-nocerts','-nodes'],env.OPENSSL_BIN);break;}catch{if(legacy)throw Error('Não foi possível abrir o certificado. Confira o arquivo A1 e a senha no servidor.');}}const candidates=[...certPem.toString('utf8').matchAll(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g)].map(m=>({pem:m[0],cert:new X509Certificate(m[0])})),key=createPrivateKey(keyPem),leaf=candidates.find(c=>c.cert.checkPrivateKey(key));if(!leaf)throw Error('A chave privada não corresponde ao certificado.');const cert=leaf.cert,chain=[leaf.pem],used=new Set([cert.fingerprint256]);let current=cert;for(let i=0;i<8;i++){const next=candidates.find(c=>!used.has(c.cert.fingerprint256)&&current.checkIssued(c.cert)&&current.verify(c.cert.publicKey));if(!next)break;used.add(next.cert.fingerprint256);if(next.cert.checkIssued(next.cert)&&next.cert.verify(next.cert.publicKey))break;chain.push(next.pem);current=next.cert;}certPem=Buffer.from(chain.join('\n'));const now=Date.now();if(Date.parse(cert.validFrom)>now||Date.parse(cert.validTo)<=now)throw Error('O certificado ainda não é válido ou está vencido.');const cnpj=certificateCnpj(cert.raw);if(cnpj!==expectedCnpj)throw Error('O CNPJ do certificado não corresponde ao CNPJ configurado na Royal.');const tlsKey=Buffer.from(key.export({format:'pem',type:'pkcs8'}));createSecureContext({cert:certPem,key:tlsKey});return{cert:certPem,key:tlsKey,metadata:{cnpj,expires_at:new Date(cert.validTo).toISOString()}};}finally{pfx.fill(0);keyPem?.fill(0);}
}
