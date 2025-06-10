<?php

namespace App\Http\Controllers\Auth;
use App\Http\Controllers\Controller;
use Illuminate\Http\Request;
use App\Models\User;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Auth;
use Tymon\JWTAuth\Facades\JWTAuth;
use Tymon\JWTAuth\Exceptions\JWTException;
use Illuminate\Auth\Events\Registered;
use Illuminate\Support\Str;
use Illuminate\Support\Facades\Mail;
use App\Mail\EmailVerificationCode;
use Illuminate\Support\Facades\Validator;
use Illuminate\Validation\ValidationException;
use Illuminate\Support\Facades\Log;


class AuthController extends Controller
{


public function register(Request $request)
{
    $validator = Validator::make($request->all(), [
        'name' => 'required|string|max:255',
        'email' => 'required|string|email|max:255|unique:users',
        'password' => 'required|string|min:8|confirmed',
    ]);

    if ($validator->fails()) {
        return response()->json([
            'status' => false,
            'message' => 'Validation failed',
            'errors' => $validator->errors(),
        ], 422);
    }

    try {
        $code = rand(10000, 99999);
        $sentAt = now();

        $user = User::create([
            'name' => $request->name,
            'email' => $request->email,
            'password' => Hash::make($request->password),
            'email_verification_code' => $code,
            'verification_code_sent_at' => $sentAt,
        ]);

        // Send verification email
        try {
            Mail::to($user->email)->send(new EmailVerificationCode($code));
        } catch (\Exception $e) {
            Log::error('Email sending failed: ' . $e->getMessage());
            return response()->json([
                'status' => false,
                'message' => 'Registered, but failed to send verification email.',
            ], 500);
        }

        // Generate JWT token
        $token = JWTAuth::fromUser($user);

        return response()->json([
            'status' => true,
            'message' => 'Registered successfully. Please verify your email.',
            'token' => $token,
        ], 201);

    } catch (\Exception $e) {
        Log::error('Registration error: ' . $e->getMessage());
        return response()->json([
            'status' => false,
            'message' => 'Something went wrong during registration.',
        ], 500);
    }
}



public function verifyEmailCode(Request $request)
{
    $request->validate([
        'email' => 'required|email',
        'code' => 'required|digits:5',
    ]);

    $user = User::where('email', $request->email)->first();

    if (!$user) {
        return response()->json(['message' => 'User not found'], 404);
    }

    // ⏰ Check if the code is expired
    $expiresAt = $user->verification_code_sent_at?->addMinutes(5);
    if (!$expiresAt || now()->greaterThan($expiresAt)) {
        // Invalidate the code
        $user->email_verification_code = null;
        $user->save();

        return response()->json([
            'message' => 'Verification code has expired. Please request a new one.',
        ], 403);
    }

    // ✅ Check code match
    if ($user->email_verification_code !== $request->code) {
        return response()->json(['message' => 'Invalid verification code'], 401);
    }

    // 🎉 Successful verification
    $user->email_verified_at = now();
    $user->email_verification_code = null; // clear the code
    $user->save();

    // 🛡️ Auto login the user by generating JWT token
    $token = JWTAuth::fromUser($user);

    return response()->json([
        'message' => 'Email verified and logged in successfully',
        'token' => $token,
        'expires_in' => auth('api')->factory()->getTTL() * 60,
    ], 200);
}


public function login(Request $request)
{
    $request->validate([
        'email' => 'required|email',
        'password' => 'required|string|min:5',
    ]);

    $credentials = $request->only('email', 'password');

    // Check if user exists by email
    $user = User::where('email', $credentials['email'])->first();
    if (!$user) {
        return response()->json([
            'success' => false,
            'errors' => ['email' => 'No account found with this email address. Please register'],
        ], 404);
    }

    try {
        if (!$token = JWTAuth::attempt($credentials)) {
            return response()->json([
                'success' => false,
                'errors' => ['password' => 'Invalid password'],
            ], 401);
        }
    } catch (JWTException $e) {
        return response()->json([
            'success' => false,
            'message' => 'Could not create token',
            'error' => $e->getMessage()
        ], 500);
    }

    return response()->json([
        'success' => true,
        'token' => $token,
        'expires_in' => auth('api')->factory()->getTTL() * 60,
    ]);
}


    public function logout()
    {
        try {
            JWTAuth::invalidate(JWTAuth::getToken());
        } catch (JWTException $e) {
            return response()->json(['error' => 'Failed to logout, please try again'], 500);
        }

        return response()->json(['message' => 'Successfully logged out']);
    }

    public function getUser()
    {
        try {
            $user = Auth::user();
            if (!$user) {
                return response()->json(['error' => 'User not found'], 404);
            }
            return response()->json($user);
        } catch (JWTException $e) {
            return response()->json(['error' => 'Failed to fetch user profile'], 500);
        }
    }

    public function updateUser(Request $request)
    {
        try {
            $user = Auth::user();
            $user->update($request->only(['name', 'email']));
            return response()->json($user);
        } catch (JWTException $e) {
            return response()->json(['error' => 'Failed to update user'], 500);
        }
    }




public function resendCode(Request $request)
{
    try {
        $token = $request->bearerToken();

        if (!$token) {
            return response()->json([
                'status' => false,
                'message' => 'Token is missing.',
            ], 401);
        }

        // Get user from token
        $user = JWTAuth::setToken($token)->toUser();

        if (!$user) {
            return response()->json([
                'status' => false,
                'message' => 'Unauthenticated.',
            ], 401);
        }

        // ✅ Check if user is already verified
        if ($user->email_verified_at !== null) {
            return response()->json([
                'status' => false,
                'message' => 'Email is already verified.',
            ], 400);
        }

        // Optional: Check if old code is still valid before resending
        // $expiryMinutes = 5;
        // if ($user->verification_code_sent_at && now()->diffInMinutes($user->verification_code_sent_at) < $expiryMinutes) {
        //     return response()->json([
        //         'status' => false,
        //         'message' => 'Verification code is still valid.',
        //     ], 400);
        // }

        // Generate new code and timestamp
        $code = rand(10000, 99999);
        $newSentAt = now();

        // Update user
        $user->update([
            'email_verification_code' => $code,
            'verification_code_sent_at' => $newSentAt,
        ]);

        // Send the email
        try {
            Mail::to($user->email)->send(new EmailVerificationCode($code));
        } catch (\Exception $e) {
            Log::error('Email sending failed: ' . $e->getMessage());
            return response()->json([
                'status' => false,
                'message' => 'Failed to send verification email.',
            ], 500);
        }

        // Generate a new token with updated claims
        $newToken = JWTAuth::fromUser($user);

        return response()->json([
            'status' => true,
            'message' => 'Verification code resent successfully.',
            'token' => $newToken,
             'email_verification_code' => $code,
            'verification_code_sent_at' => $newSentAt,
        ], 200);

    } catch (\Exception $e) {
        Log::error('Resend code error: ' . $e->getMessage());
        return response()->json([
            'status' => false,
            'message' => 'Something went wrong.',
        ], 500);
    }
}





    
}