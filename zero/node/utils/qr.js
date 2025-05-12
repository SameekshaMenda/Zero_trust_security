const QRCode = require('qrcode');
const { generateBase32Secret } = require('./otp');

const buildOTPUri = (secret, user, issuer = "ZeroTrustApp") => {
  return `otpauth://totp/${issuer}:${user}?secret=${secret}&issuer=${issuer}&algorithm=SHA1&digits=6&period=30`;
};

const generateQRCode = async (secret, user, issuer = 'ZeroTrustApp') => {
  const otpUri = buildOTPUri(secret, user, issuer);
  return await QRCode.toDataURL(otpUri);
};

const generateForUser = async (user) => {
  const secret = generateBase32Secret();
  const qrImage = await generateQRCode(secret, user);
  return { secret, qrImage };
};

module.exports = { buildOTPUri, generateQRCode, generateForUser };