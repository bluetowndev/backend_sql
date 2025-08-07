import jsonwebtoken from "jsonwebtoken";

const { verify } = jsonwebtoken;

export const authenticate = (req, res, next) => {
  // Extract token from Authorization header (format: Bearer <token>)
  const authHeader = req.headers['authorization'];
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({
      success: false,
      message: 'Access token is missing or invalid',
    });
  }

  const token = authHeader.split(' ')[1];

  try {
    // Verify the token using the JWT secret
    const decoded = verify(token, process.env.JWT_SECRET);

    // Attach decoded user data to the request object
    req.user = {
      userId: decoded.userId,
      email: decoded.email,
      role: decoded.role,
    };

    // Proceed to the next middleware or route handler
    next();
  } catch (error) {
    if (error.name === 'TokenExpiredError') {
      return res.status(401).json({
        success: false,
        message: 'Access token has expired',
      });
    }
    return res.status(401).json({
      success: false,
      message: 'Invalid access token',
    });
  }
};
