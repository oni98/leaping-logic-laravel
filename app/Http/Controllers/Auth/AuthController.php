<?php

namespace App\Http\Controllers\Auth;

use App\Http\Controllers\Controller;
use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Password;
use Illuminate\Support\Facades\Validator;
use Illuminate\Validation\ValidationException;

class AuthController extends Controller
{
    /**
     * Create a new AuthController instance.
     *
     * @return void
     */
    public function __construct()
    {
        $this->middleware('auth:api', ['except' => ['login', 'register', 'forgotPassword', 'resetPassword']]);
    }

    /**
     * Store a new User
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function register(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'name' => 'required',
            'email' => 'required|email|unique:users',
            'password' => 'required|confirmed|min:8',
        ]);
        if ($validator->fails()) {
            $data = [
                'data' => $validator->errors(),
                'error' => true,
                'code' => 500
            ];
            return response()->json($data);
        }

        $user = new User();
        $user->name = $request->name;
        $user->email = $request->email;
        $user->password = Hash::make($request->password);
        if ($user->save()) {
            $data = [
                'data' => $user,
                'status' => 'ok',
                'code' => 201
            ];
        } else {
            $data = [
                'data' => $user,
                'status' => 'nok',
                'code' => 500
            ];
        }

        return response()->json($data);
    }

    /**
     * Get a JWT via given credentials.
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function login(Request $request)
    {
        $credentials = request(['email', 'password']);

        $token = auth()->attempt($credentials);
        if (!$token) {

            $data = [
                'error' => 'Unauthorized',
                'status' => 'nok',
                'code' => 401
            ];
            return response()->json($data);
        }

        return $this->respondWithToken($token);
    }

    /**
     * Send email to reset password.
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function forgotPassword(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'email' => 'required|email',
        ]);
        if ($validator->fails()) {
            $data = [
                'data' => $validator->errors(),
                'error' => true,
                'code' => 500
            ];
            return response()->json($data);
        }

        $status = Password::sendResetLink($request->only('email'));

        if($status != Password::RESET_LINK_SENT){
            throw ValidationException::withMessages([
                'email' => [__($status)]
            ]);
        }

        return response()->json(['status' => __($status)]);
    }

    /**
     * Get the authenticated Users.
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function users(Request $request)
    {
        $limit = ($request->limit)? $request->limit : 10;
        $users = User::paginate($limit);
        $data = [
            'data' => $users,
            'status' => 'ok',
            'code' => 200
        ];
        return response()->json($data);
    }

    /**
     * Get the token array structure.
     *
     * @param  string $token
     *
     * @return \Illuminate\Http\JsonResponse
     */
    protected function respondWithToken($token)
    {
        return response()->json([
            'access_token' => $token,
            'token_type' => 'bearer',
            'expires_in' => auth()->factory()->getTTL() * 60
        ]);
    }
}
