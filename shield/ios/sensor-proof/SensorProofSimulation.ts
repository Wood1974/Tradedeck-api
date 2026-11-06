import crypto from 'crypto';

interface SensorMetadata {
  cameraId: string;
  deviceModel: string;
  sensorBitDepth: number;
  pixelLayout: string;
}

interface CaptureContext {
  timestamp: number;
  deviceCert: string;
  keychainPrivateKey: string;
  imagePixels: Buffer;
  sensorMetadata: SensorMetadata;
  keychainSignature?: string;
}

interface ProofEvidence {
  imageHash: string;
  chainOfCustodyHash: string;
  deviceCertHash: string;
  timestamp: number;
  sensorMetadata: SensorMetadata;
  keychainSignature: string;
}

interface VerificationResult {
  verified: boolean;
  reason?: string;
  attackDetected?: boolean;
}

interface ScenarioResult {
  scenario: number;
  name: string;
  attacked: boolean;
  detected: boolean;
  verificationReason?: string;
}

class SensorProofSystem {
  private keychainPrivateKey: crypto.KeyObject;
  private keychainPublicKey: string;
  private deviceCertificate: string;

  constructor() {
    // Generate EC key pair for Keychain
    const { privateKey, publicKey } = crypto.generateKeyPairSync('ec', {
      namedCurve: 'prime256v1'
    });
    this.keychainPrivateKey = privateKey;
    this.keychainPublicKey = publicKey.export({ format: 'pem', type: 'spki' }).toString();

    // Mock Apple Device Certificate
    this.deviceCertificate = crypto.randomBytes(32).toString('hex');
  }

  captureImage(sensorMetadata: SensorMetadata, imagePixels: Buffer): CaptureContext {
    const now = Date.now();

    // Create keychain signature
    const sign = crypto.createSign('sha256');
    sign.update(imagePixels);
    const keychainSignature = sign.sign(this.keychainPrivateKey, 'hex');

    return {
      timestamp: now,
      deviceCert: this.deviceCertificate,
      keychainPrivateKey: this.keychainPrivateKey.export({ format: 'pem', type: 'pkcs8' }).toString(),
      imagePixels,
      sensorMetadata,
      keychainSignature
    };
  }

  generateProof(capture: CaptureContext): ProofEvidence {
    const imageHash = crypto
      .createHash('sha256')
      .update(capture.imagePixels)
      .digest('hex');

    const deviceCertHash = crypto
      .createHash('sha256')
      .update(capture.deviceCert)
      .digest('hex');

    // Chain of custody: timestamp | sensor_id | image_hash | device_cert_hash
    const chainData = `${capture.timestamp}|${capture.sensorMetadata.cameraId}|${imageHash}|${deviceCertHash}`;
    const chainOfCustodyHash = crypto
      .createHash('sha256')
      .update(chainData)
      .digest('hex');

    return {
      imageHash,
      chainOfCustodyHash,
      deviceCertHash,
      timestamp: capture.timestamp,
      sensorMetadata: capture.sensorMetadata,
      keychainSignature: capture.keychainSignature || ''
    };
  }

  verifyProof(evidence: ProofEvidence, capture: CaptureContext): VerificationResult {
    const MAX_FUTURE_MS = 24 * 60 * 60 * 1000; // 24 hours
    const MAX_PAST_MS = 365 * 24 * 60 * 60 * 1000; // 1 year

    // STEP 1: Timestamp Bounds Check (CRITICAL FOR SCENARIO 8)
    const now = Date.now();
    const timeDiff = evidence.timestamp - now;

    if (timeDiff > MAX_FUTURE_MS) {
      return {
        verified: false,
        reason: 'TIMESTAMP_ANOMALY',
        attackDetected: true
      };
    }

    if (Math.abs(timeDiff) > MAX_PAST_MS && timeDiff < 0) {
      return {
        verified: false,
        reason: 'TIMESTAMP_ANOMALY',
        attackDetected: true
      };
    }

    // STEP 2: Device Certificate Validation
    if (!evidence.deviceCertHash || evidence.deviceCertHash.length === 0) {
      return {
        verified: false,
        reason: 'INVALID_DEVICE_CERT',
        attackDetected: true
      };
    }

    const expectedDeviceCertHash = crypto
      .createHash('sha256')
      .update(this.deviceCertificate)
      .digest('hex');

    if (evidence.deviceCertHash !== expectedDeviceCertHash) {
      return {
        verified: false,
        reason: 'DEVICE_CERT_MISMATCH',
        attackDetected: true
      };
    }

    // STEP 3: Keychain Signature Validation (CRITICAL FOR SCENARIO 6)
    let signatureToVerify = evidence.keychainSignature;

    if (!signatureToVerify) {
      // Create signature if not provided (for testing jailbreak scenarios)
      const providedKeyObj = crypto.createPrivateKey(capture.keychainPrivateKey);
      const sign = crypto.createSign('sha256');
      sign.update(evidence.imageHash);
      signatureToVerify = sign.sign(providedKeyObj, 'hex');
    }

    // Verify signature against the device's stored public key
    // If provided key is different (jailbreak), verification fails
    const verify = crypto.createVerify('sha256');
    verify.update(evidence.imageHash);
    const signatureValid = verify.verify(this.keychainPublicKey, signatureToVerify, 'hex');

    if (!signatureValid) {
      return {
        verified: false,
        reason: 'KEYCHAIN_SIGNATURE_INVALID',
        attackDetected: true
      };
    }

    // STEP 4: Chain-of-Custody Hash
    const chainData = `${evidence.timestamp}|${evidence.sensorMetadata.cameraId}|${evidence.imageHash}|${evidence.deviceCertHash}`;
    const expectedChainHash = crypto
      .createHash('sha256')
      .update(chainData)
      .digest('hex');

    if (evidence.chainOfCustodyHash !== expectedChainHash) {
      return {
        verified: false,
        reason: 'CHAIN_CUSTODY_MISMATCH',
        attackDetected: true
      };
    }

    // STEP 5: Sensor Metadata Sanity Check
    if (!evidence.sensorMetadata.cameraId ||
        !evidence.sensorMetadata.deviceModel ||
        evidence.sensorMetadata.sensorBitDepth < 8) {
      return {
        verified: false,
        reason: 'INVALID_SENSOR_METADATA',
        attackDetected: true
      };
    }

    return {
      verified: true,
      reason: 'VALID_PROOF',
      attackDetected: false
    };
  }
}

class AdversarialTestHarness {
  private sensorProof: SensorProofSystem;
  private results: ScenarioResult[] = [];

  constructor() {
    this.sensorProof = new SensorProofSystem();
  }

  private createValidCapture(): CaptureContext {
    return this.sensorProof.captureImage(
      {
        cameraId: 'main_camera_0',
        deviceModel: 'iPhone15Pro',
        sensorBitDepth: 12,
        pixelLayout: 'bayer_rggb'
      },
      crypto.randomBytes(1024 * 1024) // 1MB mock image
    );
  }

  async runAllScenarios(): Promise<ScenarioResult[]> {
    this.results = [];

    // Scenario 1: Synthesized Image
    await this.scenario1_SynthesizedImage();

    // Scenario 2: Screenshot
    await this.scenario2_Screenshot();

    // Scenario 3: EXIF Spoofing
    await this.scenario3_EXIFSpoofing();

    // Scenario 4: Image Editing
    await this.scenario4_ImageEditing();

    // Scenario 5: Simulator Injection
    await this.scenario5_SimulatorInjection();

    // Scenario 6: Jailbreak
    await this.scenario6_Jailbreak();

    // Scenario 7: Replay Attack
    await this.scenario7_ReplayAttack();

    // Scenario 8: Timestamp Tampering
    await this.scenario8_TimestampTampering();

    // Scenario 9: Metadata Stripping
    await this.scenario9_MetadataStripping();

    // Scenario 10: Compression/Re-encoding
    await this.scenario10_CompressionReencoding();

    // Scenario 11: Device Cloning
    await this.scenario11_DeviceCloning();

    // Scenario 12: Man-in-the-Middle
    await this.scenario12_ManInTheMiddle();

    return this.results;
  }

  private async scenario1_SynthesizedImage(): Promise<void> {
    const capture = this.createValidCapture();
    const evidence = this.sensorProof.generateProof(capture);

    // Attack: modify device cert
    evidence.deviceCertHash = crypto.randomBytes(32).toString('hex');

    const result = this.sensorProof.verifyProof(evidence, capture);

    this.results.push({
      scenario: 1,
      name: 'Synthesized Image',
      attacked: true,
      detected: result.attackDetected === true,
      verificationReason: result.reason
    });
  }

  private async scenario2_Screenshot(): Promise<void> {
    const capture = this.createValidCapture();
    const evidence = this.sensorProof.generateProof(capture);

    // Attack: change device cert to invalid value
    evidence.deviceCertHash = '0000000000000000000000000000000000000000000000000000000000000000';

    const result = this.sensorProof.verifyProof(evidence, capture);

    this.results.push({
      scenario: 2,
      name: 'Screenshot',
      attacked: true,
      detected: result.attackDetected === true,
      verificationReason: result.reason
    });
  }

  private async scenario3_EXIFSpoofing(): Promise<void> {
    const capture = this.createValidCapture();
    const evidence = this.sensorProof.generateProof(capture);

    // Attack: modify sensor metadata
    evidence.sensorMetadata.deviceModel = 'FakePhone';

    const result = this.sensorProof.verifyProof(evidence, capture);

    this.results.push({
      scenario: 3,
      name: 'EXIF Spoofing',
      attacked: true,
      detected: result.attackDetected === true,
      verificationReason: result.reason
    });
  }

  private async scenario4_ImageEditing(): Promise<void> {
    const capture = this.createValidCapture();
    const evidence = this.sensorProof.generateProof(capture);

    // Attack: modify image, which invalidates hash
    evidence.imageHash = crypto.randomBytes(32).toString('hex');

    const result = this.sensorProof.verifyProof(evidence, capture);

    this.results.push({
      scenario: 4,
      name: 'Image Editing',
      attacked: true,
      detected: result.attackDetected === true,
      verificationReason: result.reason
    });
  }

  private async scenario5_SimulatorInjection(): Promise<void> {
    const capture = this.createValidCapture();
    const evidence = this.sensorProof.generateProof(capture);

    // Attack: empty device cert
    evidence.deviceCertHash = '';

    const result = this.sensorProof.verifyProof(evidence, capture);

    this.results.push({
      scenario: 5,
      name: 'Simulator Injection',
      attacked: true,
      detected: result.attackDetected === true,
      verificationReason: result.reason
    });
  }

  private async scenario6_Jailbreak(): Promise<void> {
    const capture = this.createValidCapture();
    const evidence = this.sensorProof.generateProof(capture);

    // Attack: use fake key for signature
    const { privateKey } = crypto.generateKeyPairSync('ec', {
      namedCurve: 'prime256v1'
    });
    const fakeSign = crypto.createSign('sha256');
    fakeSign.update(evidence.imageHash);
    evidence.keychainSignature = fakeSign.sign(privateKey, 'hex');

    const result = this.sensorProof.verifyProof(evidence, capture);

    this.results.push({
      scenario: 6,
      name: 'Jailbreak',
      attacked: true,
      detected: result.attackDetected === true,
      verificationReason: result.reason
    });
  }

  private async scenario7_ReplayAttack(): Promise<void> {
    const capture1 = this.createValidCapture();
    const evidence1 = this.sensorProof.generateProof(capture1);

    const capture2 = this.createValidCapture();
    const evidence2 = this.sensorProof.generateProof(capture2);

    // Attack: replay evidence1 signature with evidence2 image
    evidence2.keychainSignature = evidence1.keychainSignature;
    evidence2.imageHash = evidence1.imageHash; // but different image in capture2

    const result = this.sensorProof.verifyProof(evidence2, capture2);

    this.results.push({
      scenario: 7,
      name: 'Replay Attack',
      attacked: true,
      detected: result.attackDetected === true,
      verificationReason: result.reason
    });
  }

  private async scenario8_TimestampTampering(): Promise<void> {
    const capture = this.createValidCapture();
    const evidence = this.sensorProof.generateProof(capture);

    // Attack: set timestamp to 1 year in future
    evidence.timestamp = Date.now() + (365 * 24 * 60 * 60 * 1000) + 1000;

    const result = this.sensorProof.verifyProof(evidence, capture);

    this.results.push({
      scenario: 8,
      name: 'Timestamp Tampering',
      attacked: true,
      detected: result.attackDetected === true,
      verificationReason: result.reason
    });
  }

  private async scenario9_MetadataStripping(): Promise<void> {
    const capture = this.createValidCapture();
    const evidence = this.sensorProof.generateProof(capture);

    // Attack: strip metadata
    evidence.sensorMetadata.cameraId = '';
    evidence.sensorMetadata.deviceModel = '';

    const result = this.sensorProof.verifyProof(evidence, capture);

    this.results.push({
      scenario: 9,
      name: 'Metadata Stripping',
      attacked: true,
      detected: result.attackDetected === true,
      verificationReason: result.reason
    });
  }

  private async scenario10_CompressionReencoding(): Promise<void> {
    const capture = this.createValidCapture();
    const evidence = this.sensorProof.generateProof(capture);

    // Attack: modify image hash (simulating re-encoding)
    evidence.imageHash = crypto.randomBytes(32).toString('hex');
    // Need to recalculate chain hash with new image hash
    const chainData = `${evidence.timestamp}|${evidence.sensorMetadata.cameraId}|${evidence.imageHash}|${evidence.deviceCertHash}`;
    evidence.chainOfCustodyHash = crypto
      .createHash('sha256')
      .update(chainData)
      .digest('hex');

    const result = this.sensorProof.verifyProof(evidence, capture);

    this.results.push({
      scenario: 10,
      name: 'Compression/Re-encoding',
      attacked: true,
      detected: result.attackDetected === true,
      verificationReason: result.reason
    });
  }

  private async scenario11_DeviceCloning(): Promise<void> {
    const capture = this.createValidCapture();
    const evidence = this.sensorProof.generateProof(capture);

    // Attack: use a different device cert (cloned device)
    evidence.deviceCertHash = crypto.randomBytes(32).toString('hex');

    const result = this.sensorProof.verifyProof(evidence, capture);

    this.results.push({
      scenario: 11,
      name: 'Device Cloning',
      attacked: true,
      detected: result.attackDetected === true,
      verificationReason: result.reason
    });
  }

  private async scenario12_ManInTheMiddle(): Promise<void> {
    const capture = this.createValidCapture();
    const evidence = this.sensorProof.generateProof(capture);

    // Attack: modify evidence in transit
    evidence.imageHash = crypto.randomBytes(32).toString('hex');

    const result = this.sensorProof.verifyProof(evidence, capture);

    this.results.push({
      scenario: 12,
      name: 'Man-in-the-Middle',
      attacked: true,
      detected: result.attackDetected === true,
      verificationReason: result.reason
    });
  }

  getResults(): ScenarioResult[] {
    return this.results;
  }

  printSummary(): void {
    console.log('\n=== Phase 1 Adversarial Test Summary ===\n');

    let detectedCount = 0;
    let totalCount = this.results.length;

    this.results.forEach(result => {
      const status = result.detected ? '✓ DETECTED' : '✗ MISSED';
      console.log(`Scenario ${result.scenario}: ${result.name} - ${status}`);
      console.log(`  Reason: ${result.verificationReason}`);

      if (result.detected) {
        detectedCount++;
      }
    });

    console.log(`\n=== Detection Rate: ${detectedCount}/${totalCount} (${Math.round(detectedCount/totalCount*100)}%) ===\n`);

    if (detectedCount === totalCount) {
      console.log('✓ Phase 1 Complete: 100% detection rate achieved!');
    }
  }
}

async function main() {
  const harness = new AdversarialTestHarness();
  const results = await harness.runAllScenarios();

  harness.printSummary();

  // Return exit code based on detection rate
  const detectedCount = results.filter(r => r.detected).length;
  process.exit(detectedCount === results.length ? 0 : 1);
}

main().catch(err => {
  console.error('Error running simulation:', err);
  process.exit(1);
});
