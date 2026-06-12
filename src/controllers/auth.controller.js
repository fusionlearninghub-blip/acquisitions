import { createUser } from '#services/auth.service.js';
import { formatValidationError } from '#utils/format.js';
import { generateToken } from '../utils/jwt.js';
import { cookies } from '../utils/cookies.js';
import { signupSchema } from '../validations/auth.validations.js';

export const signup = async (req, res, next) => {
  try {
    const validationResult = signupSchema.safeParse(req.body);

    if (!validationResult.success) {
      return res.status(400).json({
        error: 'Validation failed',
        details: formatValidationError(validationResult.error),
      });
    }

    const { name, email, password, role } = validationResult.data;

    const user = await createUser({
      name,
      email,
      password,
      role,
    });

    const token = generateToken({
      id: user.id,
      email: user.email,
      role: user.role,
    });

    cookies.set(res, 'token', token);

    console.log(`User registered successfully: ${email}`);

    return res.status(201).json({
      message: 'User registered successfully',
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        role: user.role,
      },
    });
  } catch (e) {
    console.error('Signup error:', e);

    if (e.message === 'User with this email already exists') {
      return res.status(409).json({
        error: 'Email already exists',
      });
    }

    return res.status(500).json({
      error: 'Internal server error',
    });
  }
};