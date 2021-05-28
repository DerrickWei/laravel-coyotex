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
    /**
     * @OA\Post(
     *      path="/api/login",
     *      summary="Log In",
     *      description="Login by email, password",
     *      operationId="authLogin",
     *      tags={"auth"},
     *      @OA\RequestBody(
     *          required=true,
     *          description="Pass user credentials",
     *          @OA\JsonContent(
     *              required={"email","password"},
     *              @OA\Property(property="email", type="string", format="email", example="user1@mail.com"),
     *              @OA\Property(property="password", type="string", format="password", example="PassWord12345"),
     *          ),
     *      ),
     *      @OA\Response(
     *          response=401,
     *          description="Wrong credentials response",
     *          @OA\JsonContent(
     *              @OA\Property(property="message", type="string", example="Sorry, wrong email or password. Please try again")
     *          )
     *      ),
     *      @OA\Response(
     *          response=200,
     *          description="Success Login",
     *          @OA\JsonContent(
     *              @OA\Property(property="user", type="object", ref="#/components/schemas/User"),
     *              @OA\Property(property="token", type="string")
     *          )
     *      )
     * )
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
    /**
     * @OA\Get(
     *      path="/api/details/{email}",
     *      summary="User details",
     *      description="Get User detials by Email",
     *      operationId="authDetails",
     *      security={ {"bearer": {} }},
     *      tags={"auth"},
     *      @OA\Response(
     *          response=401,
     *          description="Not Found",
     *          @OA\JsonContent(
     *              @OA\Property(property="message", type="string", example="Sorry, User not found")
     *          )
     *      ),
     *      @OA\Response(
     *          response=200,
     *          description="Success",
     *          @OA\JsonContent(
     *              @OA\Property(property="user", type="object", ref="#/components/schemas/User")
     *          )
     *      )
     * )
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
    /**
     * @OA\Post(
     *      path="/api/logout",
     *      summary="Logout",
     *      description="Logout user and invalidate token",
     *      operationId="authLogout",
     *      tags={"auth"},
     *      security={ {"bearer": {} }},
     *      @OA\Response(
     *          response=200,
     *          description="Success",
     *          @OA\JsonContent(
     *              @OA\Property(property="message", type="string", example="Logged Out"),
     *          )
     *      ),
     *      @OA\Response(
     *          response=401,
     *          description="Returns when user is not authenticated",
     *          @OA\JsonContent(
     *              @OA\Property(property="message", type="string", example="Not authorized"),
     *          )
     *      )
     * )
     */
    public function logout(Request $request)
    {
        auth()->user()->tokens()->delete();

        return response([
            'message' => 'Logged Out'
        ], 201);
    }
}
