<?php
/**
 * A simple, extensible cipher encryption/decryption service class.
 *
 * Requires mcrypt.
 */
class modCipher {
    /**
     * @var modX A reference to a modX instance.
     */
    public $modx = null;
    /**
     * @var array An array of configuration options.
     */
    public $config = array(
        'key' => '',
        'iv' => '',
        'algorithm' => MCRYPT_RIJNDAEL_128,
        'mode' => MCRYPT_MODE_CBC,
        'algorithm_dir' => '',
        'mode_dir' => '',
    );
    /**
     * @var resource An encryption descriptor handle.
     */
    public $ed = null;

    /**
     * Construct an instance of the modCipher service.
     *
     * @param modX $modx A modX instance to be used by reference.
     * @param array $options An array of options to merge into the config.
     */
    function __construct(modX & $modx, array $options = array()) {
        $this->modx =& $modx;
        $this->config = array_merge($this->config, $options);
    }

    /**
     * Make sure the module is closed when the object is destroyed.
     */
    function __destruct() {
        if ($this->isOpen()) {
            $this->close();
        }
    }

    /**
     * Open a specific encryption algorithm/mode and get a descriptor.
     *
     * @param string $algorithm An optional algorithm to get an encryption descriptor for.
     * @param string $mode An optional mode to get an encryption descriptor for.
     */
    public function open($algorithm = '', $mode = '') {
        if (!empty($algorithm)) $this->config['algorithm'] = $algorithm;
        if (!empty($mode)) $this->config['mode'] = $mode;
        $this->ed = mcrypt_module_open(
            $this->config['algorithm'],
            $this->config['algorithm_dir'],
            $this->config['mode'],
            $this->config['mode_dir']
        );
    }

    /**
     * Close a specific encryption descriptor.
     *
     * @return boolean True if an open module was successfully closed.
     */
    public function close() {
        $closed = false;
        if (!empty($this->ed) && is_resource($this->ed)) {
            $closed = mcrypt_module_close($this->ed);
        }
        return $closed;
    }

    /**
     * Initialize an open encryption descriptor for use.
     *
     * @return integer|boolean False if bad parameters are passed; negative integers for specific errors.
     */
    public function init() {
        return mcrypt_generic_init($this->ed, base64_decode($this->config['key']), base64_decode($this->config['iv']));
    }

    /**
     * Uninitialize an open encryption descriptor so it can be used again.
     *
     * @return boolean True if the descriptor is successfully uninitialized.
     */
    public function deinit() {
        $uninitialized = false;
        if (!empty($this->ed) && is_resource($this->ed)) {
            $uninitialized = mcrypt_generic_deinit($this->ed);
        }
        return $uninitialized;
    }

    /**
     * Indicates if an encryption descriptor is open and available.
     *
     * @return boolean True if an open encryption descriptor exists.
     */
    public function isOpen() {
        return (!empty($this->ed) && is_resource($this->ed));
    }

    /**
     * Encrypt data using the modCipher configuration.
     *
     * @param string $data A string of data to be encrypted.
     * @return string The base64_encoded, encrypted data.
     */
    public function encrypt($data) {
        if (!$this->isOpen()) $this->open();
        $this->init();
        $encrypted = base64_encode(mcrypt_generic($this->ed, $data));
        $this->deinit();
        return $encrypted;
    }

    /**
     * Decrypt data using the modCipher configuration.
     *
     * @param string $data Encrypted data to be decrypted.
     * @return string The unencrypted data.
     */
    public function decrypt($data) {
        if (!$this->isOpen()) $this->open();
        $this->init();
        $decrypted = rtrim(mdecrypt_generic($this->ed, base64_decode($data)), "\x00..\x1F");
        $this->deinit();
        return $decrypted;
    }

    /**
     * Generate a random initialization vector.
     *
     * @param int $source A source of randomness.
     * @return string A base64 encoded initialization vector.
     */
    public function generateIV($source = MCRYPT_RAND) {
        if (!$this->isOpen()) $this->open();
        return base64_encode(mcrypt_create_iv(mcrypt_enc_get_iv_size($this->ed), $source));
    }

    /**
     * Generate a secret key for use in encrypt/decrypt operations.
     *
     * @param string $string A string to generate the key from.
     * @return string A base64 encoded secret key.
     */
    public function generateKey($string) {
        if (!$this->isOpen()) $this->open();
        $keySize = mcrypt_enc_get_key_size($this->ed);
        return base64_encode(substr(md5($string), 0, $keySize));
    }
}
