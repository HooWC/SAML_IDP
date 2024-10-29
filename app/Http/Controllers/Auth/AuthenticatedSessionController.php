<?php

namespace App\Http\Controllers\Auth;

use App\Http\Controllers\Controller;
use App\Http\Controllers\Saml\SamlIdpLoginController;
use App\Http\Requests\Auth\LoginRequest;
use App\Models\AcsProvider;
use App\Models\User;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Redirect;

class AuthenticatedSessionController extends Controller
{
    /**
     * Display the login view.
     */
    public function create(Request $request)
    {
        $acsUrl = $request->query('acs_url');
        if (!$acsUrl)
            return redirect('/');

        session(['acs_url' => $acsUrl]);
        return view('auth.login');
    }

    /**
     * Handle an incoming authentication request.
     */
    public function store(LoginRequest $request)
    {
        $credentials = $request->only('email', 'password');

        if (!Auth::attempt($credentials)) {
            return redirect()->back()->withErrors([
                'email' => 'The provided credentials are incorrect.',
            ]);
        }

        $SamlIdpLoginController = new SamlIdpLoginController();
        return $SamlIdpLoginController->SendXmlToSp($request, 'login');
    }

    /**
     * Destroy an authenticated session. : RedirectResponse
     */
    public function destroy(Request $request)
    {
        $userId = Auth::id();

        $OtherAcsProvider = AcsProvider::where('user_id', $userId)
            ->where('login_status', true)
            ->get();

        if ($OtherAcsProvider) {
            foreach ($OtherAcsProvider as $acsProvider) {
                dump($acsProvider->acs_url);
//                $firstAcsUrl = $acsProvider->acs_url;
//                $acsProvider->login_status = false;
//                $acsProvider->save();
//
//                $spFirstUrl = $firstAcsUrl . 'logoutIDP?BackUrl=' . config('services.idp.idp_splogout');
//                return Redirect::to($spFirstUrl);
            }
        }

        dump('come');
//
//        Auth::guard('web')->logout();
//        $request->session()->regenerateToken();
        sleep(10);
        return redirect('/');
//        return response()->json([
//           'trest' => 122
//        ]);
    }
}
