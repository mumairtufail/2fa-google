<?php

namespace App\Http\Controllers;

use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;
use PragmaRX\Google2FALaravel\Google2FA;

use BaconQrCode\Renderer\ImageRenderer;
use BaconQrCode\Renderer\Image\SvgImageBackEnd;
use BaconQrCode\Renderer\RendererStyle\RendererStyle;
use BaconQrCode\Writer;
use Illuminate\Support\Facades\Storage;



class AuthController extends Controller
{
    protected $google2fa;

    public function __construct(Google2FA $google2fa)
    {
        $this->google2fa = $google2fa;
    }

// public function setup2FA(Request $request)
//     {
//         $user = $request->user();
        
//         // Use the injected Google2FA instance
//         $secret = $this->google2fa->generateSecretKey();
//         $user->google2fa_secret = $secret;
//         $user->save();
    
//         $qrCodeUrl = $this->google2fa->getQRCodeUrl(
//             config('app.name'),
//             $user->email,
//             $secret
//         );
    
//         return response()->json([
//             'message' => '2FA setup successful',
//             'secret' => $secret,
//             'qr_code_url' => $qrCodeUrl
//         ]);
//     }



public function setup2FA(Request $request)
{
    $user = $request->user();
    
    // Use the injected Google2FA instance
    $secret = $this->google2fa->generateSecretKey();
    $user->google2fa_secret = $secret;
    $user->save();

    $qrCodeUrl = $this->google2fa->getQRCodeUrl(
        config('app.name'),
        $user->email,
        $secret
    );

    // Generate QR code SVG
    $renderer = new ImageRenderer(
        new RendererStyle(400),
        new SvgImageBackEnd()
    );
    $writer = new Writer($renderer);
    $qrCodeSvg = $writer->writeString($qrCodeUrl);

    // Save the SVG file
    $fileName = 'qrcodes/' . $user->id . '.svg';
    Storage::disk('public')->put($fileName, $qrCodeSvg);

    // Generate the URL to the SVG file
    $qrCodeUrl = Storage::url($fileName);

    return response()->json([
        'message' => '2FA setup successful',
        'secret' => $secret,
        'qr_code_url' => 'localhost:8000'. $qrCodeUrl
    ]);
}

    public function register(Request $request)
    {
        $request->validate([
            'name' => 'required|string',
            'email' => 'required|string|email|unique:users',
            'password' => 'required|string',
        ]);

        $user = User::create([
            'name' => $request->name,
            'email' => $request->email,
            'password' => Hash::make($request->password),
        ]);

        return response()->json([
            'message' => 'User registered successfully',
            'user' => $user,
            'token' => $user->createToken('auth_token')->plainTextToken

        ], 201);
    }

    public function login(Request $request)
    {
        $request->validate([
            'email' => 'required|string|email',
            'password' => 'required|string',
        ]);
    
        $user = User::where('email', $request->email)->first();
    
        if (!$user || !Hash::check($request->password, $user->password)) {
            return response()->json([
                'message' => 'Invalid credentials'
            ], 401);
        }
    
       
        if ($user->google2fa_secret) {
            try {
                $request->validate([
                    'code' => 'required|string',
                ]);
            } catch (\Illuminate\Validation\ValidationException $e) {
                return response()->json([
                    'message' => 'Code is required as 2FA is enabled'
                ], 422);
            }

    
            $valid = $this->google2fa->verifyKey($user->google2fa_secret, $request->code);
    
            if (!$valid) {
                return response()->json([
                    'message' => 'Invalid 2FA code'
                ], 401);
            }
        }
    
        return response()->json([
            'message' => 'Login successful',
            'user' => $user,
            'token' => $user->createToken('auth_token')->plainTextToken
        ]);
    }

    public function verify2FA(Request $request)
    {
        $request->validate([
            'email' => 'required|string|email',
            'code' => 'required|string',
        ]);


        $user = User::where('email', $request->email)->first();
        if (!$user) {
            return response()->json([
                'message' => 'User not found'
            ], 404);
        }


        $valid = $this->google2fa->verifyKey($user->google2fa_secret, $request->code);

        if ($valid) {
            return response()->json([
                'message' => '2FA verification successful',
                'user' => $user,
                'token' => $user->createToken('auth_token')->plainTextToken
            ]);
        }

        return response()->json([
            'message' => 'Invalid 2FA code'
        ], 401);
    }
}