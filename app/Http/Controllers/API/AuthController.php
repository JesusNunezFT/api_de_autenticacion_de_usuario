<?php

namespace App\Http\Controllers\API;

use App\Http\Controllers\Controller;
use App\Models\User;
use Illuminate\Support\Facades\Validator;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Contracts\Service\Attribute\Required;
use Illuminate\Support\Facades\Cookie;


class AuthController extends Controller
{

    public function register(Request $request)
    {
        //validacion de los datos
        // $request->validate([
        //         'name' => 'required|',
        //         'email' => 'required|email|password|unique:users',
        //         'password' => 'required|confirmed',
        //     ]);
        $validator = Validator::make($request->all(), [
            'name' => ['required'],
            'email' => ['required', 'string', 'max:255', 'unique:users,email'],
            'password' => ['required', 'min:8']
        ]);
        if ($validator->fails()) {
            return response()->json($validator->errors(), 422);
        }

        //alta del usuario
        $User  = new User();
        $User->name = $request->name;
        $User->email = $request->email;
        $User->password =  Hash::make($request->password);
        $User->save();
        //alta exitosa        
        // //respuesta
        // return response()->json([
        //     "message" => "Metodo REGISTER ok"
        // ]);
        return response($User, Response::HTTP_CREATED);
    }


    public function login(Request $request)
    {
        $credentials = Validator::make($request->all(), [

            'email' => ['required', 'email'],
            'password' => ['required']
        ]);
        if (Auth::attempt($request->all())) {
            $user = Auth::user();

            $token = $user->createToken('token')->plainTextToken;
            $cookie = cookie('cookie_token', $token, 60 * 24);
            return response(["token" => $token], Response::HTTP_OK)->withoutCookie($cookie);
            return response()->json([
                'token' => $token
            ]);
        } else {
            return response(["message" => "Credenciales Invalidas"], Response::HTTP_UNAUTHORIZED);
        }
    }

    public function userProfile(Request $request)
    {

        return response()->json([
            "message" => "Metodo userProfile ok",
            "userData" => auth()->user()
        ],Response::HTTP_OK);
    }

    public function logout(){
        $cookie = Cookie::forget('cookie_token');
        return response(["message"=> "Cierre de sesion Ok"], Response::HTTP_OK)->withCookie($cookie);

    }

    public function allUsers()
    {

        $users = User::all();
        return response()->json([
            "users" => $users
        ]);
    }
}
