const jose = require('node-jose');
const { randomBytes } = require('crypto');
const fs = require('fs');

async function jweEncrypt(alg, contentKeyEncMethod, publicKey, payload) {
  const keyStore = jose.JWK.createKeyStore();
  const jwk = await keyStore.add(publicKey, 'pem');

  // Generate a random Content Encryption Key (CEK)
  const cek = randomBytes(32); // Adjust the key size according to your requirements

  // Ensure payload is a Buffer
  const payloadBuffer = Buffer.from(payload);

  // Use jose.JWE.createEncrypt directly
  const jwe = await jose.JWE.createEncrypt({
    format: 'compact',
    contentAlg: alg,
    fields: { enc: contentKeyEncMethod, kid: jwk.kid },
  }, jwk, payloadBuffer);

  return jwe;
}





async function jwsSign(privateKey, payloadToSign) {
  const keyStore = jose.JWK.createKeyStore();
  const jwk = await keyStore.add(privateKey, 'pem');

  const jws = await jose.JWS.createSign({ fields: { alg: 'RS256' } }, jwk, payloadToSign);
  const signedResult = await jws.final();
  return signedResult;
}

async function jweDecrypt(privateKey, jweEncryptedPayload) {
  const keyStore = jose.JWK.createKeyStore();
  const jwk = await keyStore.add(privateKey, 'pem');

  const jwe = await jose.JWE.createDecrypt(jwk, { format: 'compact' }, jweEncryptedPayload);
  const decryptedValue = await jwe.final();

  return decryptedValue;
}

async function jwsSignatureVerify(publicKey, signedPayloadToVerify) {
  const keyStore = jose.JWK.createKeyStore();
  const jwk = await keyStore.add(publicKey, 'pem');

  const jws = await jose.JWS.createVerify(jwk, { format: 'compact' }, signedPayloadToVerify);
  const verifiedPayload = await jws.verify(signedPayloadToVerify);

  return { signatureValid: true, payloadAfterVerification: verifiedPayload.payload };
}

async function jweEncryptAndSign(publicKeyToEncrypt, privateKeyToSign, payloadToEncryptAndSign) {
  const alg = 'RSA-OAEP-256';
  const enc = 'A256GCM';

  // Step 1: Encrypt the payload
  const encryptedPayload = await jweEncrypt(alg, enc, publicKeyToEncrypt, payloadToEncryptAndSign);

  // Step 2: Create a JWS (JSON Web Signature) for the entire JWE token
  const jwsSignature = await jwsSign(privateKeyToSign, encryptedPayload);

  // Combine the encrypted payload and JWS signature
  const encryptedAndSigned = encryptedPayload + '.' + jwsSignature;

  return encryptedAndSigned;
}


async function jweVerifyAndDecrypt(publicKeyToVerify, privateKeyToDecrypt, payloadToVerifyAndDecrypt) {
  const parts = payloadToVerifyAndDecrypt.split('.');
  const jweEncryptedPayload = parts.slice(0, -1).join('.');
  const jwsSignature = parts.pop();

  const jwVerifyObject = await jwsSignatureVerify(publicKeyToVerify, jwsSignature);

  if (!jwVerifyObject.signatureValid) {
    return null;
  } else {
    return await jweDecrypt(privateKeyToDecrypt, jweEncryptedPayload);
  }
}

function readKeyFromFile(filePath) {
  return fs.readFileSync(filePath, 'utf8');
}

// Replace the file paths with the actual private and public key files
const privateKeyString = `
-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC/8Vjz1glMyPv0
YsGyo27lufueO47Ba1Oa9zIMN3J57MLUf0dIcGLPYSMA290ktFkCrUdj0XJE3yPq
Ba2QHMsM83zbi02FQ+HcIRoCio0xeY1olV0FCQy3JcSjcqdJmuR8JMEX8Dt7p0vw
Nrt1n/2rDTEPkWpBjyWdc5eLSOKEW7r76V21Vy0aARBEV+RcpK+yXR7ZA/94m/bj
ZvcFxXYXajB4RJvWKrgwhSuQDvuu9oAyxIoy/XLKDUX6eWNAXjLoozR2PiXYNRNy
0eJ8bfSqv5FkcEmhoI83XvK9eM1P6wqXbJ+rn0FHNyM9aMmZj1dz7GOW7E6DU0Ep
ZCa3DE7tAgMBAAECggEAAgW2dLc8GNmDQhNqTAoJyJTZkFS7T9FkK51QIy3QYHV8
pgWDSEGa4Ol6l285mMHnsC4IMwaJaC1bsQMHTZ3oC8Zi+eMxWWaaMhoNLpqsGynX
MhNkzAFI54MX28sA9TcTEjXG7QwkbEyacbj556bcYtl8O1hCYNdzw4FsxtRpQpC6
K4ArsflG5JTqWqM7IvJdIR4aC7PiNHmMDpWf7gGQFaWnl7jN6bM23h2SN4nAJO55
iImHmdiAb25nnbdKc9omfs3ktTbs74Ka07AHtuMRdsF/6xbTiPYVQ7Tzh0lRDZve
xDteN9uZgtbe4YySIpaAfZdXkk7ouX+lkpbCY76RVwKBgQDMp/FIzRf4TiCgWPQv
tIZ0Cg6qTBuBs8xDGt5cFVZwn3PwMuV441uRaInx9p4ENiiP8kXAUNydMvf97x4E
l65yGtYRfe52HmOP4F3VAtp4v191c4oiRQj1uCOnC2nC1+1dmwygl7Ckqlw6QqWz
ML+KeXLjBYbmwf7bx8Wz4Q/lFwKBgQDwGOTqZzzYiHjWaTnlKJTX7wiCVy0dDn8N
o/KiHseYk63d4jw8hz7oALpoFmUJA8o+eZEW2/kPc40DyElTe8nDC5Jeb0VvbN+p
pobPxsWXDJIYYtAMYEGAvCOqhLMnyQb9ldBZ06zaXVDpMdXtYhZmD9rDPxkE/FNx
V9tCREx2mwKBgQDEF+sGcZWVEu8KFRGsIBJwXy6cGB6HEYsXhUgn/T383ZvOPEZJ
pbeYRQ1f7YiMyoPlISOaWSB581tRUet2RQweQv54diyluwp00mu17Wz+I4hI1rM1
kOY74vsuVK46xoCmnyjjO1VDAgUqwa9ZWc091o6xXhtbQeh8GBej+nMrcwKBgBZf
i31YT3AyD2iTd6SmCnCwwo86xmZtwmMoAuUejyTlpg8GFOzjAXanEre+Vn3nj4IQ
2/dQWj4ZW2udz09rOprlSidooQTIFXN+pBNah3ES585D7vUoRxJS9dPe977eWbtp
qXelZPcYOQDx9uhe+o1aLt2A1LkFNlVahYEAUku/AoGAa5HC1Xqa5RlWyDbvLyKj
IT2zNA2+3CCemJGpoy7W5vceBDHumc4fm2V1KsFllHVmZaVolKAyAzVVqp0/L4Ts
1BznLrYclqXFeIG5vUw77FlzKakSCrltfmZEgLbG49GZwajHruhwJTtrdU0/WwvH
rwT93M7Rh8W8gvuN497C+Tg=
-----END PRIVATE KEY-----
`;
const publicKeyString  = `-----BEGIN CERTIFICATE-----
MIIDrjCCApYCAQEwDQYJKoZIhvcNAQELBQAwgasxCzAJBgNVBAYTAklOMRQwEgYD
VQQIDAtNYWhhcmFzaHRyYTEPMA0GA1UEBwwGTXVtYmFpMRIwEAYDVQQKDAlBeGlz
IEJhbmsxETAPBgNVBAsMCEFQSSBUZWFtMSUwIwYDVQQDDBxVQVQgSW50ZXJtZWRp
YXRlIENlcnRpZmljYXRlMScwJQYJKoZIhvcNAQkBFhhhcGkuY29ubmVjdEBheGlz
YmFuay5jb20wHhcNMjQwMTE2MTIzNTMwWhcNMjUwMjAxMTIzNTMwWjCBjTELMAkG
A1UEBhMCSU4xDzANBgNVBAgMBlB1bmphYjEPMA0GA1UEBwwGTW9oYWxpMQ8wDQYD
VQQKDAZQYWlzc28xDDAKBgNVBAsMA0RhYjEMMAoGA1UEAwwDRGFiMS8wLQYJKoZI
hvcNAQkBFiBhbmt1c2gudGhha3VyQGhlbGlvc3RlY2hsYWJzLmNvbTCCASIwDQYJ
KoZIhvcNAQEBBQADggEPADCCAQoCggEBAKhoMCS28d5cw8KMZQR2Q3N7DWOH3pxB
x9Aao5wnnj7em1F5UOSngONAQaih9QHJ4xkAUc3Bw4wjzMiwoflvUJOsy5pVf/I3
01WT9M9IhsDGBUxjFK99HZHE3SqOOfuFU+M9Bv575K8eWwU0Z+LZkbclo/b3b/d6
eBM1H67aIVDLrFDF3v+s62Ian9SiMja0l47B6N4C+V57KbbCIBbHSUadkjiuqvlB
TpoK9Q583ABcbDpUyD0aHc9SQd6NQ6iKwidnkt3m1S8DvFL6j0FHtWFAy5QRK5WX
gyemvuk4zcofSrnHYXSGrtC55RIjHKn46y9VuNZFgph0dN5TTKzCwdsCAwEAATAN
BgkqhkiG9w0BAQsFAAOCAQEAKDWnFhEwWY+jpQORIOYxPcPNQAzW5BZM/y4U+0LX
QgsSP1+nAWP8LXciLoXR33ryXOKJV/Zk9ZwXp+J5/MyQTqYAVqNIpForzcY1SUdV
FggdvgzXvi6Irxfbi6w4fXLUQhQvxGQn6dwx5yGlLXnLpEWxHc+aQWRKXf357Gno
JbcaB9a7bGu2xIyevYgPkSJp+MRA90WoKPkTWazVR32SYs10XHoaEE1Y0z13aTyv
uZJRlaMfE1f+sDm26s++Suvfx9oTU2QUGixc/fPFi+9mRngsbqXrjj4uybO3+u7W
LobX8b6nELsfMd2NTyIVS6AUuilPiiiZ6NjZ9fnyv2HD+g==
-----END CERTIFICATE-----`;

// Example usage
(async () => {
  try {
    const payload = {
    "Data": {
        "userName": "alwebuser",
        "password": "acid_qa",
    },
    "Risks": {},
};
    const encryptedAndSigned = await jweEncryptAndSign(publicKeyString, privateKeyString, payload);
    console.log('Encrypted and Signed:', encryptedAndSigned);

    const decryptedAndVerified = await jweVerifyAndDecrypt(publicKeyString, privateKeyString, encryptedAndSigned);
    console.log('Decrypted and Verified:', decryptedAndVerified);
  } catch (error) {
    console.error(error);
  }
})();
