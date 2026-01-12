# Nafath MFA API Documentation

⚠️ postman collection attaches with the repo
## Overview
Nafath MFA (Multi-Factor Authentication) API provides secure user verification through Saudi Arabia's Nafath service. The API allows users to authenticate using their national ID through a mobile application.

## Frontend Routes & Requirements

### Frontend Integration Flow

#### 1. User Authentication Page
**Required Actions**:
- Display national ID input field
- Handle createRequest API call
- Show random code to user for Nafath app verification
- Implement polling mechanism for status checking

#### 2. API Calls Sequence
```javascript
// Step 1: Create Nafath Request
const createNafathRequest = async (nationalId) => {
    const response = await fetch('/api/v1/nafath/request', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({
            nationalId: nationalId
        })
    });

    const data = await response.json();

    if (data.success) {
        // Show random code to user
        displayRandomCode(data.data.random);

        // Start polling for status
        startStatusPolling(nationalId);
    }
};

// Step 2: Poll Status (every 3-5 seconds)
const startStatusPolling = async (nationalId) => {
    const pollInterval = setInterval(async () => {
        const response = await fetch('/api/v1/nafath/status', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                nationalId: nationalId
            })
        });

        const data = await response.json();

        if (data.success) {
            const status = data.data.status;

            if (status === 'COMPLETED') {
                clearInterval(pollInterval);
                // User authenticated successfully
                handleAuthenticationSuccess(data.data.user);
            } else if (status === 'REJECTED' || status === 'EXPIRED') {
                clearInterval(pollInterval);
                // Handle rejection/expiration
                handleAuthenticationFailure(status);
            }
            // Continue polling for WAITING status
        }
    }, 3000); // Poll every 3 seconds
};
```

#### 3. UI Requirements
- **National ID Input**: Text field with validation
- **Random Code Display**: Large, prominent display of the random code
- **Status Messages**: Clear feedback for different states
- **Loading States**: Show progress during API calls and polling
- **Error Handling**: User-friendly error messages

#### 4. User Experience Flow
1. User enters national ID
2. System generates and displays random code
3. User opens Nafath app and approves request
4. Frontend polls for status updates
5. On completion: User logged in with JWT token
6. On rejection/expiration: Show appropriate message

## API Endpoints

### Base URL
```
POST /api/v1/nafath/{endpoint}
```

### Available Endpoints

#### 1. Create Nafath Request
```http
POST /api/v1/nafath/request
```

**Request Body**:
```json
{
  "nationalId": "string (required)"
}
```

**Response Success**:
```json
{
  "success": true,
  "message": "NAFATH MFA request created",
  "data": {
    "random": "string"
  }
}
```

#### 2. Check Nafath Status
```http
POST /api/v1/nafath/status
```

**Request Body**:
```json
{
  "nationalId": "string (required)"
}
```

**Response Success (WAITING)**:
```json
{
  "success": true,
  "message": "Request status retrieved",
  "data": {
    "status": "WAITING"
  }
}
```

**Response Success (COMPLETED)**:
```json
{
  "success": true,
  "message": "User account created successfully",
  "data": {
    "status": "COMPLETED",
    "user": {
      "id": "integer",
      "name": "string",
      "email": "string|null",
      "phone": "string|null",
      "identity_number": "string",
      "token": "string"
    }
  }
}
```

## Backend Implementation

### 1. Routes (`routes/api/v1/website.php`)

```php
<?php

use App\Http\Controllers\Api\V1\Nafath\NafathController;
use Illuminate\Support\Facades\Route;

// ... other routes ...

Route::group(['prefix' => 'nafath', 'controller' => NafathController::class], function () {
    Route::post('/request', 'createRequest');
    Route::post('/status', 'checkStatus');
});

// ... other routes ...
```

### 2. Controller (`app/Http/Controllers/Api/V1/Nafath/NafathController.php`)

```php
<?php

namespace App\Http\Controllers\Api\V1\Nafath;

use App\Http\Controllers\Controller;
use App\Http\Requests\Api\V1\Nafath\CheckNafathStatusRequest;
use App\Http\Requests\Api\V1\Nafath\CreateNafathRequestRequest;
use App\Http\Services\Api\V1\Nafath\NafathService;

class NafathController extends Controller
{
    public function __construct(
        private readonly NafathService $nafathService,
    ) {
    }

    /**
     * Create a new Nafath MFA request
     */
    public function createRequest(CreateNafathRequestRequest $request)
    {
        return $this->nafathService->createRequest($request->validated());
    }

    /**
     * Check Nafath MFA request status
     */
    public function checkStatus(CheckNafathStatusRequest $request)
    {
        return $this->nafathService->checkStatus($request->validated());
    }
}
```

### 3. Request Classes

#### CreateNafathRequestRequest (`app/Http/Requests/Api/V1/Nafath/CreateNafathRequestRequest.php`)

```php
<?php

namespace App\Http\Requests\Api\V1\Nafath;

use Illuminate\Foundation\Http\FormRequest;

class CreateNafathRequestRequest extends FormRequest
{
    /**
     * Determine if the user is authorized to make this request.
     */
    public function authorize(): bool
    {
        return true;
    }

    /**
     * Get the validation rules that apply to the request.
     *
     * @return array<string, \Illuminate\Contracts\Validation\ValidationRule|array<mixed>|string>
     */
    public function rules(): array
    {
        return [
            'nationalId' => ['required', 'string', 'regex:/^[1234569]{1}\d{9}$/'],
        ];
    }
}
```

#### CheckNafathStatusRequest (`app/Http/Requests/Api/V1/Nafath/CheckNafathStatusRequest.php`)

```php
<?php

namespace App\Http\Requests\Api\V1\Nafath;

use Illuminate\Foundation\Http\FormRequest;

class CheckNafathStatusRequest extends FormRequest
{
    /**
     * Determine if the user is authorized to make this request.
     */
    public function authorize(): bool
    {
        return true;
    }

    /**
     * Get the validation rules that apply to the request.
     *
     * @return array<string, \Illuminate\Contracts\Validation\ValidationRule|array<mixed>|string>
     */
    public function rules(): array
    {
        return [
            'nationalId' => ['required', 'string', 'regex:/^[123456]{1}\d{9}$/'],
        ];
    }
}
```

### 4. Service Layer (`app/Http/Services/Api/V1/Nafath/NafathService.php`)

```php
<?php

namespace App\Http\Services\Api\V1\Nafath;

use App\Http\Traits\Responser;
use App\Models\NafathRequest;
use App\Models\User;
use App\Repository\UserRepositoryInterface;
use Exception;
use GuzzleHttp\Client;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Str;

class NafathService
{
    use Responser;

    private Client $client;

    private string $baseUrl;

    private string $appId;

    private string $appKey;

    public function __construct(
        private readonly UserRepositoryInterface $userRepository,
    ) {
        $this->baseUrl = config('services.nafath.base_url');
        $this->appId = config('services.nafath.app_id');
        $this->appKey = config('services.nafath.app_key');

        $this->client = new Client([
            'base_uri' => $this->baseUrl,
            'timeout' => 30,
            'headers' => [
                'Content-Type' => 'application/json;charset=utf-8',
                'Accept' => 'application/json;charset=utf-8',
            ],
        ]);
    }

    /**
     * Create a new MFA request
     */
    public function createRequest(array $data): \Illuminate\Http\JsonResponse
    {
        DB::beginTransaction();
        try {
            // Generate values in backend
            $requestId = Str::uuid()->toString();
            $local = 'ar'; // Default to Arabic
            $nationalId = $data['nationalId'];
            $service = config('services.nafath.service', 'RequestDigitalServicesEnrollment');

            // Check if request_id already exists (very unlikely with UUID, but just in case)
            $existingRequest = NafathRequest::where('request_id', $requestId)->first();
            if ($existingRequest) {
                // Regenerate if exists (extremely rare)
                $requestId = Str::uuid()->toString();
            }

            // Prepare request payload
            $requestPayload = [
                'nationalId' => $nationalId,
                'service' => $service,
            ];

            // Call Nafath API
            $response = $this->client->post('/api/v1/mfa/request', [
                'headers' => [
                    'APP-ID' => $this->appId,
                    'APP-KEY' => $this->appKey,
                ],
                'query' => [
                    'local' => $local,
                    'requestId' => $requestId,
                ],
                'json' => $requestPayload,
            ]);

            $responseBody = json_decode($response->getBody()->getContents(), true);

            // Store request in database
            $nafathRequest = NafathRequest::create([
                'national_id' => $nationalId,
                'service' => $service,
                'request_id' => $requestId,
                'local' => $local,
                'trans_id' => $responseBody['transId'] ?? null,
                'random' => $responseBody['random'] ?? null,
                'request_payload' => $requestPayload,
                'response_payload' => $responseBody,
                'status' => 'WAITING',
                'callback_url' => null, // Can be set from config if needed
            ]);

            DB::commit();

            return $this->responseSuccess(
                message: __('messages.NAFATH MFA request created'),
                data: [
                    // 'transId' => $nafathRequest->trans_id,
                    'random' => $nafathRequest->random,
                    // 'requestId' => $nafathRequest->request_id,
                ]
            );
        } catch (\GuzzleHttp\Exception\ClientException $e) {
            DB::rollBack();

            // Handle 400 Bad Request - Active Transaction
            if ($e->getResponse() && $e->getResponse()->getStatusCode() === 400) {
                try {
                    $responseBody = json_decode($e->getResponse()->getBody()->getContents(), true);
                    $message = $responseBody['message'] ?? 'Invalid Request';

                    // Check if it's "There Is Active Trx" error
                    if (str_contains($message, 'Active Trx') || str_contains($message, 'Active')) {
                        // Find the active request - check WAITING status first, then any recent request
                        $activeRequest = NafathRequest::where('national_id', $data['nationalId'])
                            ->where('status', 'WAITING')
                            ->latest()
                            ->first();

                        // If no WAITING request found, check for the most recent request (might be expired but not updated)
                        if (! $activeRequest) {
                            $activeRequest = NafathRequest::where('national_id', $data['nationalId'])
                                ->where('status', 'WAITING')
                                ->latest()
                                ->first();
                        }

                        if ($activeRequest) {
                            return $this->responseSuccess(
                                message: __('messages.Active request found'),
                                data: [
                                    // 'transId' => $activeRequest->trans_id,
                                    'random' => $activeRequest->random,
                                    // 'requestId' => $activeRequest->request_id,
                                ]
                            );
                        }

                        // If no request found in DB but API says there's an active one, return the error
                        Log::warning('Nafath: API reports active transaction but no request found in DB for nationalId: '.$data['nationalId']);
                    }

                    Log::error('Nafath createRequest 400 error: '.$message);

                    return $this->responseFail(
                        status: 400,
                        message: __('messages.Validation error'),
                        data: [
                            'error' => $message,
                        ]
                    );
                } catch (\Exception $parseException) {
                    Log::error('Nafath createRequest error parsing response: '.$parseException->getMessage());
                }
            }

            Log::error('Nafath createRequest error: '.$e->getMessage());

            return $this->responseFail(
                status: 500,
                message: __('messages.Something went wrong'),
                data: [
                    'error' => app()->environment('local') ? $e->getMessage() : null,
                ]
            );
        } catch (Exception $e) {
            DB::rollBack();
            Log::error('Nafath createRequest error: '.$e->getMessage());

            return $this->responseFail(
                status: 500,
                message: __('messages.Something went wrong'),
                data: [
                    'error' => app()->environment('local') ? $e->getMessage() : null,
                ]
            );
        }
    }

    /**
     * Check MFA request status
     */
    public function checkStatus(array $data): \Illuminate\Http\JsonResponse
    {
        try {
            // $transId = $data['transId'];
            // $random = $data['random'];
            $nationalId = $data['nationalId'];

            // Find the request
            $nafathRequest = NafathRequest::where('national_id', $nationalId)
                ->where('status', 'WAITING')
                ->latest()
                ->first();

            if (! $nafathRequest) {
                return $this->responseFail(
                    status: 404,
                    message: __('messages.Request not found')
                );
            }

            // Call Nafath API to check status
            $response = $this->client->post('/api/v1/mfa/request/status', [
                'headers' => [
                    'APP-ID' => $this->appId,
                    'APP-KEY' => $this->appKey,
                ],
                'json' => [
                    'transId' => $nafathRequest->trans_id,
                    'random' => $nafathRequest->random,
                    'nationalId' => $nationalId,
                ],
            ]);

            $responseBody = json_decode($response->getBody()->getContents(), true);
            $status = $responseBody['status'] ?? 'WAITING';

            // Update request status
            $nafathRequest->update([
                'status' => $status,
                'response_payload' => array_merge($nafathRequest->response_payload ?? [], $responseBody),
            ]);

            // If status is COMPLETED, create user account
            if ($status === 'COMPLETED' && ! $nafathRequest->user_id) {
                DB::beginTransaction();
                try {
                    // Check if user already exists with this national ID
                    $existingUser = User::where('identity_number', $nationalId)->first();

                    if ($existingUser) {
                        // User already exists, link the request
                        $nafathRequest->update(['user_id' => $existingUser->id]);

                        DB::commit();

                        return $this->responseSuccess(
                            message: __('messages.User account found'),
                            data: [
                                'status' => $status,
                                'user' => [
                                    'id' => $existingUser->id,
                                    'name' => $existingUser->name,
                                    'email' => $existingUser->email,
                                    'phone' => $existingUser->phone,
                                    'identity_number' => $existingUser->identity_number,
                                    'token' => $existingUser->token(), // JWT token
                                ],
                            ]
                        );
                    }

                    // Create new user account
                    // Generate default values since frontend doesn't send them
                    $userData = [
                        'name' => 'User '.substr($nationalId, -4),
                        'email' => null,
                        'phone' => null,
                        'password' => Hash::make(Str::random(12)),
                        'identity_number' => $nationalId,
                        'otp_verified' => true,
                        'is_active' => true,
                    ];

                    $user = $this->userRepository->create($userData);

                    // Create wallet for the user
                    $user->wallet()->create(['balance' => 0]);

                    // Link user to nafath request
                    $nafathRequest->update(['user_id' => $user->id]);

                    DB::commit();

                    return $this->responseSuccess(
                        message: __('messages.User account created successfully'),
                        data: [
                            'status' => $status,
                            'user' => [
                                'id' => $user->id,
                                'name' => $user->name,
                                'email' => $user->email,
                                'phone' => $user->phone,
                                'identity_number' => $user->identity_number,
                                'token' => $user->token(), // JWT token
                            ],
                        ]
                    );
                } catch (Exception $e) {
                    DB::rollBack();
                    Log::error('Nafath createUser error: '.$e->getMessage());

                    return $this->responseFail(
                        status: 500,
                        message: __('messages.Failed to create user account'),
                        data: [
                            'error' => app()->environment('local') ? $e->getMessage() : null,
                        ]
                    );
                }
            } elseif ($status === 'EXPIRED') {
                $nafathRequest->update([
                    'status' => 'EXPIRED',
                ]);
            } elseif ($status === 'REJECTED') {
                $nafathRequest->update([
                    'status' => 'REJECTED',
                ]);
            }

            return $this->responseSuccess(
                message: __('messages.Request status retrieved'),
                data: [
                    'status' => $status,
                    // 'transId' => $nafathRequest->trans_id,
                    // 'random' => $nafathRequest->random,
                ]
            );
        } catch (Exception $e) {
            Log::error('Nafath checkStatus error: '.$e->getMessage());

            return $this->responseFail(
                status: 500,
                message: __('messages.Something went wrong'),
                data: [
                    'error' => app()->environment('local') ? $e->getMessage() : null,
                ]
            );
        }
    }
}
```

## Database Models

### NafathRequest Model
**Table**: `nafath_requests`

**Fields**:
- `national_id`: User's national ID
- `service`: Nafath service type
- `request_id`: Internal UUID
- `local`: Language ('ar')
- `trans_id`: Nafath transaction ID
- `random`: Random code for user
- `request_payload`: Request data sent to Nafath
- `response_payload`: Response data from Nafath
- `status`: Request status (WAITING, COMPLETED, EXPIRED, REJECTED)
- `callback_url`: Callback URL (optional)
- `user_id`: Linked user ID (nullable)

### User Model
**Table**: `users`

**Fields** (relevant to Nafath):
- `identity_number`: National ID (used for linking)
- `name`, `email`, `phone`: User information
- `otp_verified`: Set to true for Nafath-verified users
- `is_active`: Set to true for new users
- `password`: Hashed password

## Configuration Requirements

Add to `config/services.php`:
```php
'nafath' => [
    'base_url' => env('NAFATH_BASE_URL'),
    'app_id' => env('NAFATH_APP_ID'),
    'app_key' => env('NAFATH_APP_KEY'),
    'service' => env('NAFATH_SERVICE', 'RequestDigitalServicesEnrollment'),
],
```

Add to `.env`:
```env
NAFATH_BASE_URL=https://nafath.api.url
NAFATH_APP_ID=your_app_id
NAFATH_APP_KEY=your_app_key
NAFATH_SERVICE=RequestDigitalServicesEnrollment
```

## Flow Diagrams

### Frontend Flow
```
User enters National ID → API: Create Request → Display Random Code → User opens Nafath App → Poll Status → Handle Result
```

### Backend Flow
```
Create Request: Validation → Generate UUID → Nafath API → Store DB → Return Random
Check Status: Find Request → Nafath Status API → Update DB → Create/Link User → Return Status
```

### Status Values
- **WAITING**: Request initiated, waiting for user action
- **COMPLETED**: User approved in Nafath app
- **EXPIRED**: Request timed out
- **REJECTED**: User rejected the request
