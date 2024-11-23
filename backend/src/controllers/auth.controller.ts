import { Request, Response } from 'express';
import prisma from '../db/prisma';
import bcryptjs from 'bcryptjs';
import generateToken from '../utils/generateToken';

export const signup = async (req: Request, res: Response) => {
  try {
    const { fullName, username, password, confirmPassword, gender } = req.body;

    if (!fullName || !username || !password || !confirmPassword || !gender) {
      res.status(400).json({ error: 'please fill in all fields' });

      return;
    }

    if (password !== confirmPassword) {
      res.status(400).json({ error: 'Passwords do not match' });
      return;
    }

    const user = await prisma.user.findUnique({ where: { username } });

    if (user) {
      res.status(400).json({ error: 'Username already exists' });

      return;
    }

    const salt = await bcryptjs.genSalt(10);
    const hashPassword = await bcryptjs.hash(password, salt);

    const boyProfilePic = `https://avatar.iran.liara.run/public/boy?username=${username}`;
    const girlProfilePic = `https://avatar.iran.liara.run/public/girl?username=${username}`;

    const newUser = await prisma.user.create({
      data: {
        fullName,
        username,
        password: hashPassword,
        gender,
        profilePic: gender === 'male' ? boyProfilePic : girlProfilePic,
      },
    });

    if (newUser) {
      generateToken(newUser.id, res);

      res.status(201).json({
        id: newUser.id,
        fullName: newUser.fullName,
        username: newUser.username,
        profilePic: newUser.profilePic,
      });
      return;
    }
    res.status(400).json({ error: 'invalid data' });
  } catch (e: any) {
    console.log(`Error in signup controller ${e.message}`);
    res.status(500).json({ error: 'Internal Server Error' });
  }
};

export const login = async (req: Request, res: Response) => {
  try {
    const { username, password } = req.body;

    if (!username || !password) {
      res.status(400).json({ error: 'please fill in all fields' });
      return;
    }

    const user = await prisma.user.findUnique({ where: { username } });
    if (!user) {
      res.status(400).json({ error: `Can't find username: ${username}` });
      return;
    }

    const isPasswordCorrect = await bcryptjs.compare(password, user.password);
    if (!isPasswordCorrect) {
      res.status(400).json({ error: 'Invalid Password!' });
      return;
    }

    generateToken(user.id, res);

    res.status(201).json({
      id: user.id,
      fullName: user.fullName,
      username: user.username,
      profilePic: user.profilePic,
    });
  } catch (e: any) {
    console.log(`Error in login controller ${e.message}`);
    res.status(500).json({ error: 'Internal Server Error' });
  }
};

export const logout = async (req: Request, res: Response) => {
  try {
    res.cookie('jwt', '', { maxAge: 0 });
    res.status(200).json({ message: 'Logged out successfully' });
  } catch (e: any) {
    console.log(`Error in logout controller ${e.message}`);
    res.status(500).json({ error: 'Internal Server Error' });
  }
};

export const getMe = async (req: Request, res: Response) => {
  try {
    const user = await prisma.user.findUnique({ where: { id: req.user.id } });

    if (!user) {
      res.status(400).json({ error: 'User not found' });
      return;
    }

    res.status(200).json({
      id: user.id,
      fullName: user.fullName,
      username: user.username,
      profilePic: user.profilePic,
    });
  } catch (e: any) {
    console.log(`Error in logout controller ${e.message}`);
    res.status(500).json({ error: 'Internal Server Error' });
  }
};
