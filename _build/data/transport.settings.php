<?php
/**
 * @package modcipher
 */
$settings = array();

$settings['modcipher.class_path']= $modx->newObject('modSystemSetting');
$settings['modcipher.class_path']->fromArray(array(
    'key' => 'modcipher.class_path',
    'value' => '{core_path}components/modcipher/model/',
    'xtype' => 'textfield',
    'namespace' => 'modcipher',
    'area' => 'security',
),'',true,true);

$settings['modcipher.class']= $modx->newObject('modSystemSetting');
$settings['modcipher.class']->fromArray(array(
    'key' => 'modcipher.class',
    'value' => 'modx.cipher.modCipher',
    'xtype' => 'textfield',
    'namespace' => 'modcipher',
    'area' => 'security',
),'',true,true);
