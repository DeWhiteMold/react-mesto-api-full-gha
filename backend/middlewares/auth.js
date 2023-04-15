const jwt = require('jsonwebtoken');
const AuthError = require('../errors/AuthError');

const handleAuthError = () => {
  throw new AuthError('Необходима авторизация');
};

const extractBearerToken = (header) => header.replace('Bearer ', '');

module.exports = (req, res, next) => {
  const { authorization } = req.headers;

  if (!authorization || !authorization.startsWith('Bearer ')) {
    return handleAuthError();
  }

  const token = extractBearerToken(authorization);
  const { JWT_SECRET, NODE_ENV } = process.env;
  let payload;

  try {
    payload = jwt.verify(token, NODE_ENV === 'production' ? JWT_SECRET : 'secret-token');
  } catch (err) {
    return handleAuthError();
  }

  req.user = payload;

  return next();
};
