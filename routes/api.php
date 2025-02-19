<?php


use App\Http\Controllers\AuthController;

Route::prefix('auth')->group(function () {
    // Public routes
    Route::post('/register', [AuthController::class, 'apiRegister']);
    Route::post('/login', [AuthController::class, 'apiLogin']);

    // Password reset routes
    Route::post('/password/reset', [AuthController::class, 'sendResetLinkEmail']);
    Route::post('/password/reset/confirm', [AuthController::class, 'resetPassword']);

    // Protected routes (require authentication)
    Route::middleware('auth:sanctum')->group(function () {
        Route::post('/logout', [AuthController::class, 'apiLogout']);
        // Add other protected routes here, e.g.:
        // Route::get('/profile', [AuthController::class, 'apiProfile']);
    });
});
