<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Str;
use App\Models\Customer;
use Illuminate\Support\Facades\Validator;

class AuthController extends Controller
{
    public function apiRegister(Request $request)
    {
        $request->validate([
            'name' => ['required', 'string', 'regex:/^[a-zA-Z\s]+$/', 'max:255'],
            'email' => 'required|string|email|max:255|unique:customers',
            'password' => 'required|string|min:8',
        ]);

        $customer = Customer::create([
            'name' => $request->name,
            'email' => $request->email,
            'password' => Hash::make($request->password),
        ]);

        return response()->json([
            'message' => 'Customer registered successfully',
            'customer' => $customer,
        ], 201);
    }

    public function apiLogin(Request $request)
    {
        try {
            // Log::debug('Login request received', [
            //     'ip' => $request->ip(),
            //     'user_agent' => $request->userAgent()
            // ]);
            
            $validator = Validator::make($request->all(), [
                'email' => ['required', 'email'],
                'password' => ['required'],
            ]);

            if ($validator->fails()) {
                // Log::error('Login validation failed', [
                //     'errors' => $validator->errors(),
                //     'input' => $request->except('password')
                // ]);
                return response()->json([
                    'message' => 'Validation error',
                    'errors' => $validator->errors()
                ], 422);
            }

            $credentials = $request->only('email', 'password');
            // Log::debug('Attempting login with credentials', [
            //     'email' => $credentials['email'],
            //     'ip' => $request->ip()
            // ]);

            $customer = Customer::where('email', $credentials['email'])->first();
            
            if ($customer && Hash::check($credentials['password'], $customer->password)) {
                // Log::info('Login successful', [
                //     'email' => $credentials['email'],
                //     'ip' => $request->ip()
                // ]);
                
                $token = $customer->createToken('authToken')->plainTextToken;

                return response()->json([
                    'message' => 'Login successful',
                    'customer' => $customer,
                    'token' => $token,
                ]);
            }

            // Log::warning('Invalid login attempt', [
            //     'email' => $credentials['email'],
            //     'ip' => $request->ip()
            // ]);
            return response()->json([
                'message' => 'Invalid credentials',
                'error' => 'Authentication failed'
            ], 401);
        } catch (\Exception $e) {
            // Log::error('Login error', [
            //     'error' => $e->getMessage(),
            //     'trace' => $e->getTraceAsString(),
            //     'ip' => $request->ip()
            // ]);
            return response()->json([
                'message' => 'Internal server error',
                'error' => $e->getMessage()
            ], 500);
        }
    }

    public function apiLogout(Request $request)
    {
        $request->user()->currentAccessToken()->delete();

        return response()->json([
            'message' => 'Logged out successfully',
        ]);
    }

    public function sendResetLinkEmail(Request $request)
    {
        $request->validate(['email' => 'required|email|exists:customers,email']);

        $token = Str::random(60);
        DB::table('password_reset_tokens')->updateOrInsert(
            ['email' => $request->email],
            ['token' => Hash::make($token), 'created_at' => now()]
        );

        $resetLink = url('/password/reset?token='.$token);
        Log::info('Password reset link generated for '.$request->email.': '.$resetLink);

        return response()->json([
            'message' => 'Password reset link generated successfully.',
            'reset_link' => $resetLink,
            'instructions' => 'Use this link to reset your password. The link will expire in 60 minutes.'
        ]);
    }

    public function resetPassword(Request $request)
    {
        $request->validate([
            'email' => 'required|email|exists:customers,email',
            'token' => 'required|string',
            'password' => 'required|string|min:8|confirmed',
        ]);

        $reset = DB::table('password_reset_tokens')
            ->where('email', $request->email)
            ->first();

        if (!$reset || !Hash::check($request->token, $reset->token)) {
            return response()->json(['message' => 'Invalid token'], 400);
        }

        Customer::where('email', $request->email)
            ->update(['password' => Hash::make($request->password)]);

        DB::table('password_reset_tokens')
            ->where('email', $request->email)
            ->delete();

        return response()->json([
            'message' => 'Password reset successfully',
        ]);
    }
}
