import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import { db } from '../db/index.js';
import { users } from '../models/user.model.js';
import { eq } from 'drizzle-orm';

export const createUser = async ({
  name,
  email,
  password,
  role = 'user',
}) => {
  const existingUser = await db.query.users.findFirst({
    where: eq(users.email, email),
  });

  if (existingUser) {
    throw new Error('User with this email already exists');
  }

  const hashedPassword = await bcrypt.hash(password, 10);

  const [user] = await db
    .insert(users)
    .values({
      name,
      email,
      password: hashedPassword,
      role,
    })
    .returning();

  return user;
};

export const loginUser = async ({ email, password }) => {
  const user = await db.query.users.findFirst({
    where: eq(users.email, email),
  });

  if (!user) {
    throw new Error('Invalid email or password');
  }

  const isPasswordValid = await bcrypt.compare(
    password,
    user.password
  );

  if (!isPasswordValid) {
    throw new Error('Invalid email or password');
  }

  const token = jwt.sign(
    {
      id: user.id,
      email: user.email,
      role: user.role,
    },
    process.env.JWT_SECRET,
    {
      expiresIn: '15m',
    }
  );

  return {
    token,
    user: {
      id: user.id,
      name: user.name,
      email: user.email,
      role: user.role,
    },
  };
};

export const logoutUser = async () => {
  return true;
};