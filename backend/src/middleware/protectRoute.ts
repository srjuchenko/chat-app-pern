import jwt, { JwtPayload } from 'jsonwebtoken';

import { Request, Response, NextFunction } from 'express';
import prisma from '../db/prisma';

interface DecodedToken extends JwtPayload {
  userId: string;
}

declare global {
  namespace Express {
    export interface Request {
      user: {
        id: string;
      };
    }
  }
}

export const protectRoute = async (
  req: Request,
  res: Response,
  next: NextFunction
) => {
  try {
    const token = req.cookies.jwt;

    if (!token) {
      res.status(401).json({ error: 'Unauthorized - No token provided' });
      return;
    }

    const decoded = jwt.verify(token, process.env.JWT_SECRET!) as DecodedToken;
    if (!decoded) {
      res.status(401).json({ error: 'Unauthorized - Invalid Token!' });
      return;
    }

    const user = await prisma.user.findUnique({
      where: { id: decoded.userId },
      select: { id: true, username: true, fullName: true, profilePic: true },
    });

    if (!user) {
      res.status(404).json({ error: 'User not found' });
      return;
    }

    req.user = user;

    next();
  } catch (e: any) {
    console.log('error in protect route', e.message);
    res.status(500).json({ error: 'Internal server error!' });
  }
};

export default protectRoute;
