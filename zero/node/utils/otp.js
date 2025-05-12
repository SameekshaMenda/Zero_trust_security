const crypto = require('crypto');

// Custom Base32 implementation to avoid external dependencies
const Base32 = {
  alphabet: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567',
  encode: (buffer) => {
    let result = '';
    const view = new Uint8Array(buffer);
    
    for (let i = 0; i < view.length; i += 5) {
      result += Base32.alphabet[view[i] >> 3];
      result += Base32.alphabet[((view[i] & 0x07) << 2) | (view[i+1] >> 6)];
      result += Base32.alphabet[(view[i+1] & 0x3e) >> 1];
      result += Base32.alphabet[((view[i+1] & 0x01) << 4) | (view[i+2] >> 4)];
      result += Base32.alphabet[((view[i+2] & 0x0f) << 1) | (view[i+3] >> 7)];
      result += Base32.alphabet[(view[i+3] & 0x7c) >> 2];
      result += Base32.alphabet[((view[i+3] & 0x03) << 3) | (view[i+4] >> 5)];
      result += Base32.alphabet[view[i+4] & 0x1f];
    }
    
    // Replace padding
    return result.replace(/=+$/, '');
  },
  decode: (str) => {
    const buffer = [];
    const view = new Uint8Array(str.length * 5 / 8 | 0);
    
    for (let i = 0, j = 0; i < str.length; i += 8) {
      const a = Base32.alphabet.indexOf(str[i]);
      const b = Base32.alphabet.indexOf(str[i+1]);
      const c = Base32.alphabet.indexOf(str[i+2]);
      const d = Base32.alphabet.indexOf(str[i+3]);
      const e = Base32.alphabet.indexOf(str[i+4]);
      const f = Base32.alphabet.indexOf(str[i+5]);
      const g = Base32.alphabet.indexOf(str[i+6]);
      const h = Base32.alphabet.indexOf(str[i+7]);
      
      view[j++] = (a << 3) | (b >> 2);
      view[j++] = ((b & 0x03) << 6) | (c << 1) | (d >> 4);
      view[j++] = ((d & 0x0f) << 4) | (e >> 1);
      view[j++] = ((e & 0x01) << 7) | (f << 2) | (g >> 3);
      view[j++] = ((g & 0x07) << 5) | h;
    }
    
    return Buffer.from(view);
  }
};

// Generate Base32 secret
const generateBase32Secret = () => {
  return Base32.encode(crypto.randomBytes(10));
};

// Verify TOTP manually
const verifyTOTP = (secret, otp, window = 1) => {
  const getHOTPToken = (secret, intervalsNo) => {
    const key = Base32.decode(secret);
    const msg = Buffer.alloc(8);
    msg.writeBigInt64BE(BigInt(intervalsNo), 0);
    
    const hmac = crypto.createHmac('sha1', key).update(msg).digest();
    const o = hmac[19] & 0xf;
    const token = (
      ((hmac[o] & 0x7f) << 24) |
      ((hmac[o + 1] & 0xff) << 16) |
      ((hmac[o + 2] & 0xff) << 8) |
      (hmac[o + 3] & 0xff)
    ) % 1000000;
    
    return token.toString().padStart(6, '0');
  };

  const timestep = 30;
  const currentInterval = Math.floor(Date.now() / 1000 / timestep);
  
  for (let i = -window; i <= window; i++) {
    if (getHOTPToken(secret, currentInterval + i) === otp) {
      return true;
    }
  }
  
  return false;
};

module.exports = { generateBase32Secret, verifyTOTP, Base32 };