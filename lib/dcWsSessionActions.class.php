<?php

/*
 * This file is part of the symfony package.
 * (c) 2004-2006 Fabien Potencier <fabien.potencier@symfony-project.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

/**
 * Web service authentication.
 *
 * @package    symfony
 * @subpackage plugin
 * @author     Fabien Potencier <fabien.potencier@symfony-project.com>
 * @version    SVN: $Id: actions.class.php 7634 2008-02-27 18:01:40Z fabien $
 */
class dcWsSessionActions extends sfActions
{
  /**
   * Executes login action
   *
   * @ws-enable
   *
   * @param string $username username
   * @param string $password password
   *
   * @return int session_key
   */
  public function executeLogin($request)
  {
    $username = $request->getParameter('username');
    $password = $request->getParameter('password');

    $user_class = sfConfig::get('app_dcWsSessionPlugin_user_class', 'sfGuardUser')."Peer";
    $user_username_field = strtoupper(sfConfig::get('app_dcWsSessionPlugin_user_username_field', 'username'));
    $user_password_field = strtoupper(sfConfig::get('app_dcWsSessionPlugin_user_password_field', 'password'));
    $user_password_algorithm = sfConfig::get('app_dcWsSessionPlugin_user_password_algorithm', 'sha1');

    // user's salt is needed, so retrieve the user.
    $c = new Criteria();
    $c->add(constant($user_class."::".$user_username_field), $username);
    $user = call_user_func(array($user_class, "doSelectOne"), $c);

    if (!$user)
      throw new Exception("Invalid login");

    // and now make password validation
    $c = new Criteria();
    $c->add(constant($user_class."::".$user_username_field), $username);
    $c->add(constant($user_class."::".$user_password_field), call_user_func($user_password_algorithm, ($user_class == 'sfGuardUserPeer'?$user->getSalt():'').$password));

    if ($user = call_user_func(array($user_class, "doSelectOne"), $c))
    {
      $session_key = rand(1, 99999);

      $dc_ws_session = new dcWsSession();
      $dc_ws_session->setSessionKey($session_key);
      $dc_ws_session->setTs(date('Y-m-d H:i:s'));
      $dc_ws_session->setIp($_SERVER['REMOTE_ADDR']);
      $dc_ws_session->save();

      $this->result = $session_key;
    }
    else
    {
      throw new Exception("Invalid login");
    }
  }

  protected function validateSessionKey($session_key)
  {
    // delete old session keys
    $session_time = sfConfig::get('app_dcWsSecurityPlugin_session_time', 20);
    $timestamp = mktime(date('H'), date('i') - $session_time, date('s'), date("m"), date("d"), date("Y"));

    $c = new Criteria();
    $c->add(dcWsSessionPeer::TS, $timestamp, Criteria::LESS_THAN);
    dcWsSessionPeer::doDelete($c);

    $c = new Criteria();
    $c->add(dcWsSessionPeer::SESSION_KEY, $session_key);
    $c->add(dcWsSessionPeer::IP, $_SERVER['REMOTE_ADDR']);

    return dcWsSessionPeer::doSelectOne($c);
  }

  public function preExecute()
  {
    if ($this->getActionName() != 'login')
    {
      $session_key = $this->getRequest()->getParameter('session_key');
      if (!$this->validateSessionKey($session_key))
        throw new Exception("Invalid login");
    }
  }
}
