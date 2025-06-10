<?php

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;
use App\Http\Controllers\Auth\AuthController;
use App\Http\Controllers\Auth\EmailVerificationController;
use Illuminate\Support\Facades\Mail;
use App\Mail\EmailVerificationCode;
Route::get('/user', function (Request $request) {
    return $request->user();
})->middleware('auth:sanctum');

// Route::get('/test-email', function () {
//     $code = rand(10000, 99999);
//     Mail::to('laylaabosaad@gmail.com')->send(new EmailVerificationCode($code));
//     return response()->json(['message' => 'Test email sent']);
// });
Route::get('/', function () {
    return response()->json(['message' => 'Hello world!']);
});

Route::post('/register', [AuthController::class, 'register']);
Route::post('/login', [AuthController::class, 'login']);
Route::post('/email/verify-code', [AuthController::class, 'verifyEmailCode']);

 Route::put('/resend-code', [AuthController::class, 'resendCode']);
// Protect routes - JWT + email verified
Route::middleware('jwt')->group(function () {
    Route::get('/user', [AuthController::class, 'getUser']);
    Route::post('/logout', [AuthController::class, 'logout']);
    Route::put('/user', [AuthController::class, 'updateUser']); 
   
});

