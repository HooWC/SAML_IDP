<?php

namespace App\Http\Controllers\Saml;

use App\Http\Controllers\Controller;
use App\Models\AcsProvider;
use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Redirect;
use Illuminate\Support\Facades\Auth;

class SamlIdpLoginController extends Controller
{
    public function SendXmlToSp(Request $request, $type)
    {
        // 验证用户提供的凭据
        $credentials = $request->only('email', 'password');

        $password = $request->password;
        if ($password)
            $request->session()->put('user_password', $password);
        else
            $password = $request->session()->get('user_password');

        $acsUrl = $request->input('acs_url');

        if (Auth::attempt($credentials)) {
            $assertion = $this->generateSamlAssertion($request->user(), $password);

            $userId = $request->user()->id;

            $userAcsProvider = AcsProvider::where('user_id', $userId)
                ->where('acs_url', $acsUrl)
                ->first();

            if ($userAcsProvider) {
                $userAcsProvider->login_status = true;
                $userAcsProvider->save();
            } else {
                AcsProvider::create([
                    'user_id' => $userId,
                    'acs_url' => $acsUrl,
                    'login_status' => true,
                ]);
            }

            $redirectUrl = $acsUrl;
            if ($type === 'login')
                $redirectUrl .= 'login';
            else
                $redirectUrl .= 'register';

            $redirectUrl .= '?SAMLResponse=' . urlencode($assertion);
            $redirectUrl .= '&Metadata=' . config('services.idp.idp_metadata');

            return Redirect::to($redirectUrl);
        }

        //凭据验证失败，返回错误消息
        return response()->json(['error' => 'Invalid credentials'], 401);
    }

    private function generateSamlAssertion($user, $password)
    {
        // 创建 XMLWriter 实例
        $xml = new \XMLWriter();
        $xml->openMemory();
        $xml->startDocument('1.0', 'UTF-8');
        $xml->startElementNS('saml', 'Assertion', 'urn:oasis:names:tc:SAML:2.0:assertion');
        $xml->writeAttribute('ID', '_' . uniqid());
        $xml->writeAttribute('IssueInstant', now()->toIso8601ZuluString());
        $xml->writeAttribute('Version', '2.0');

        // 添加 Issuer
        $xml->startElement('Issuer');
        $xml->text('YourIssuerName');
        $xml->endElement(); // Issuer

        // 添加 Subject
        $xml->startElement('Subject');
        $xml->startElement('User');
        $xml->writeAttribute('Format', 'urn:oasis:names:tc:SAML:2.0:nameid-format:persistent');
        $xml->text($user); // 用户标识
        $xml->endElement(); // NameID
        $xml->endElement(); // Subject

        // 添加 Password
//        $xml->startElement('Password');
//        $xml->text($password); // TOTP 用户密码
//        $xml->endElement(); // Password

        // 添加 AuthnStatement
        $xml->startElement('AuthnStatement');
        $xml->writeAttribute('AuthnInstant', now()->toIso8601ZuluString());
        $xml->writeAttribute('SessionIndex', '_session_id_' . uniqid());
        $xml->endElement(); // AuthnStatement

        // 关闭 Assertion 元素
        $xml->endElement(); // Assertion
        $xml->endDocument();

        // 获取要签名的数据
        $dataToSign = $xml->outputMemory();
        return $dataToSign;
    }

    public function logout(Request $request)
    {
        $userId = Auth::id();
        $user = User::find($userId);
        $AcsProviders = $user->acsProviders;

        $logoutURL = $request->query('logout');

        if ($logoutURL && $AcsProviders) {
            // 關閉第一個sp
            session([$userId . 'logout_url' => $logoutURL]);

            $LogoutAcsProvider = AcsProvider::where('user_id', $userId)
                ->where('acs_url', $logoutURL)
                ->first();

            if ($LogoutAcsProvider) {
                $LogoutAcsProvider->login_status = false;
                $LogoutAcsProvider->save();
            }
        }

        $OtherAcsProvider = AcsProvider::where('user_id', $userId)
            ->where('login_status', true)
            ->get();

        if ($OtherAcsProvider) {
            // 關閉其他sp
            foreach ($OtherAcsProvider as $acsProvider) {
                $firstAcsUrl = $acsProvider->acs_url;
                $acsProvider->login_status = false;
                $acsProvider->save();

                $spFirstUrl = $firstAcsUrl . 'logoutIDP?BackUrl=' . config('services.idp.idp_splogout');
                return Redirect::to($spFirstUrl);
            }
        }

        $logoutURL = session($userId . 'logout_url', '');
        Auth::guard('web')->logout();
        $request->session()->regenerateToken();
        return redirect($logoutURL);
    }

    public function checkLogin(Request $request)
    {
        $acs_url = $request->session()->get('acs_url');
        $password = $request->session()->get('user_password');
        $idp_dashboard = $request->query('idp_dashboard');

        if (!$acs_url || $idp_dashboard === 'idp')
            return view('dashboard');

        $assertion = $this->generateSamlAssertion($request->user(), $password);

        $userId = $request->user()->id;

        $userAcsProvider = AcsProvider::where('user_id', $userId)
            ->where('acs_url', $acs_url)
            ->first();

        if ($userAcsProvider) {
            $userAcsProvider->login_status = true;
            $userAcsProvider->save();
        } else {
            AcsProvider::create([
                'user_id' => $userId,
                'acs_url' => $acs_url,
                'login_status' => true,
            ]);
        }

        $redirectUrl = $acs_url . 'login';
        $redirectUrl .= '?SAMLResponse=' . urlencode($assertion);
        $redirectUrl .= '&Metadata=' . config('services.idp.idp_metadata');

        return Redirect::to($redirectUrl);
    }
}
