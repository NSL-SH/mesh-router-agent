import { describe, it } from "mocha";
import { expect } from "chai";
import forge from "node-forge";
import { caCertificateChanged } from "../services/CertificateManager.js";

function makeCa(cn: string): string {
  const keys = forge.pki.rsa.generateKeyPair(1024);
  const cert = forge.pki.createCertificate();
  cert.publicKey = keys.publicKey;
  cert.serialNumber = "01";
  cert.validity.notBefore = new Date(Date.now() - 3600_000);
  cert.validity.notAfter = new Date(Date.now() + 3600_000);
  const attrs = [{ name: "commonName", value: cn }];
  cert.setSubject(attrs);
  cert.setIssuer(attrs);
  cert.sign(keys.privateKey, forge.md.sha256.create());
  return forge.pki.certificateToPem(cert);
}

describe("caCertificateChanged", () => {
  const caA = makeCa("Mesh Router CA");
  const caB = makeCa("Mesh Router CA"); // same name, new key: a regenerated CA

  it("is false for the same CA, whatever the line endings or trailing whitespace", () => {
    expect(caCertificateChanged(caA, caA)).to.equal(false);
    expect(caCertificateChanged(caA, caA.replace(/\r?\n/g, "\r\n") + "\n\n")).to.equal(false);
  });

  it("is true for a regenerated CA with the same subject", () => {
    expect(caCertificateChanged(caA, caB)).to.equal(true);
  });

  it("is true when the stored CA does not parse", () => {
    expect(caCertificateChanged("garbage", caA)).to.equal(true);
  });
});
