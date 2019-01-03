<?php
/**
 * Created by PhpStorm.
 * User: gatsby
 * Date: 2018/10/2
 * Time: 15:55
 */

namespace Liuling\Sign;

use Yii;
use yii\base\Component;
use yii\base\InvalidConfigException;

class SignCheck extends Component
{
    public $secret = '';
    public function init()
    {
        parent::init();
        if (empty($this->secret))
            throw new InvalidConfigException('third party Service: secret must be set.');
    }

    /**
     * 检查请求签名是否有效
     * @return bool
     */
    public function requestVerify()
    {
        $headers = Yii::$app->request->getHeaders();
        if (empty($headers->get('X-TOKEN')) || empty($headers->get('X-TimeStamp'))) {
            return false;
        }
//        echo json_encode(['data' => $queryParams, 'calculateSign' => $calculateSign, 'x-token' => $headers->get('X-TOKEN')]); exit(0);
        return hash_equals($this->getSign(), $headers->get('X-TOKEN'));
    }

    /**
     * 根据请求数据获取到签名
     *  如果是 post/patch 方法，那么参数应当是完成的 body 字符串；
     *  get/delete 方法， 参数会是组装的字符串，签名会先按参数名排序并将参数中的数组数据提取出来处理
     * @param $queryData
     * @return bool|string
     */
    public function getSign()
    {
        $headers = Yii::$app->request->getHeaders();
        $timestamp = $headers->get('X-TimeStamp');
        $queryParams = Yii::$app->request->getQueryParams();
        $bodyParams = Yii::$app->request->getBodyParams();
        if (!empty($queryParams)) {
            if (isset($queryParams['parent_controller'])) {
                unset($queryParams['parent_controller']);
            }
            if (isset($queryParams['r'])) {
                unset($queryParams['r']);
            }
            $queryParams = http_build_query($this->_getParamsToHmacData($queryParams));
            $queryParams = preg_replace('/%5B(\d+)%5D/', '%5B%5D', $queryParams);
        } else {
            $queryParams = '';
        }
        $bodyParams = !empty($bodyParams) ? json_encode($bodyParams) : '';
        $params = 'timestamp:' . $timestamp . "\n" . $queryParams . "\n" . $bodyParams;
        $sign = base64_encode(hash_hmac('sha256', $params, $this->secret, true));
        return $sign;
    }

    /**
     * 转换 get 请求的参数为用于计算 hmac 的数据
     * @param $data
     * @return mixed
     */
    private function _getParamsToHmacData($data)
    {
        ksort($data);
        foreach ($data as $key => $value) {
            if (is_array($value)) {
                $value = $this->_getParamsToHmacData($value);
                $data[$key] = $value;
            }
        }
        return $data;
    }
}
