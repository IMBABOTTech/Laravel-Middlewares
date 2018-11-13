<?php
/**
 * Created by PhpStorm.
 * User: 11476
 * Date: 2018/11/11
 * Time: 15:34
 */

namespace Middlewares;

use Carbon\Carbon;
use Closure;
use Illuminate\Session\TokenMismatchException;
use Illuminate\Http\Request;

/**
 * Class CSRFProtectionForFullSeparation
 * @package App\Http\Middleware
 */
class CSRFProtectionForFullSeparation
{
    /**
     * @var mixed|null
     */
    protected $SecretKey = null;
    /**
     * @var string
     */
    protected $encryptMethod = "AES-128-ECB";
    /**
     * @var null
     */
    protected $iv = null;
    /**
     * @var int
     */
    protected $options = 0;

    /**
     * CSRFProtectionForFullSeparation constructor.
     */
    public function __construct()
    {
        $this->SecretKey = env('CSRF_Protection_For_FullSeparation_SecretKey');
    }

    /**
     * Handle an incoming request.
     *
     * @param \Illuminate\Http\Request $request
     * @param \Closure $next
     * @return mixed
     * @throws TokenMismatchException
     */
    public function handle(Request $request, Closure $next)
    {

        if(!$request->isMethod('get')){
            if(!$this->CSRFVerify($request)){
                throw new TokenMismatchException;
            }
        }
        return $next($request);
    }

    /**
     * Used to set Encrypt Information
     *
     * @param $encryptMethod
     * @param int $iv
     * @param int $options
     * @return $this
     */
    public function setEncryptMethod($encryptMethod, $iv = 0, $options = 0){
        $this->encryptMethod = $encryptMethod;
        $this->iv = $iv;
        $this->options = $options;

        return $this;
    }

    /**
     * Handler Encrypt Method, you can extends this class and
     * modify this method to change the encryption method of the CSRF Protection
     *
     * @param $data
     * @return string
     */
    public function encrypt($data){
        return sha1($data);
    }

    /**
     * Handle the CSRF Protection
     *
     * @param $request
     * @return bool
     */
    protected function CSRFVerify($request){
        if(empty($request->header('X-Request-Timestamp'))){
            return false;
        }
        if(empty($request->header('X-Request-CSRFToken'))){
            return false;
        }

        if(Carbon::createFromTimestampUTC($request->header('X-Request-Timestamp'))->addMinutes(30)->lt(Carbon::now())){
            return false;
        }

        $data = $this->SecretKey . $request->header('X-Request-Timestamp') . json_encode($request->post()) . $this->SecretKey;

        $encryptResult = $this->encrypt($data);

        return ($request->header('X-Request-CSRFToken') == $encryptResult);
    }
}
