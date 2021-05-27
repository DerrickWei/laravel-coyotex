<?php

namespace App\Http\Controllers;

use App\Models\User;

use Illuminate\Http\Request;
use Illuminate\Http\Response;
use Illuminate\Support\Facades\Hash;

class AuthController extends Controller
{
    /**
     * Login API
     * 
     * @param  \Illuminate\Http\Request  $request
     * @return \Illuminate\Http\Response
     */
    public function login(Request $request) 
    {
        $fields = $request->validate([
            'email' => 'required|string',
            'password'  => 'required|string'
        ]);

        // Check if User existed
        $user = User::where('email', $fields['email'])->first();
        if (!$user || !Hash::check($fields['password'], $user->password)) {
            return response([
                'message' => 'Sorry, wrong email or password. Please try again'
            ], 401);
        }

        $token = $user->createToken('laravel-coyotex')->plainTextToken;

        $response = [
            'user'  => $user,
            'token' => $token
        ];

        return response($response, 201);
    }

    /**
     * User Details API, get user data from user model
     * 
     * @param  string   $email
     * @return \Illuminate\Http\Response
     */
    public function details($email)
    {
        // Check if User existed
        $user = User::where('email', $email)->first();
        if (!$user) {
            return response([
                'message' => 'Sorry, User not found'
            ], 401);
        } else {
            $response = [
                'user'  => $user
            ];
    
            return response($response, 201);
        }
    }

    /**
     * Logout API, delete token
     * 
     * @param  \Illuminate\Http\Request  $request
     * @return \Illuminate\Http\Response
     */
    public function logout(Request $request)
    {
        auth()->user()->tokens()->delete();

        return response([
            'message' => 'Logged Out'
        ], 201);
    }
}
