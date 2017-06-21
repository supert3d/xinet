<?php


class Xinet_API {
	
	public $isAuth = false; 
	public $server = NULL;  
	public $request; // (mixed) Request object. // NOT USED
	public $httpCode; // HTTP status code from request. 
	
	public $cacheThumbs = true; 
	public $thumbCacheDir; 
	
	public $applicationCats = array(); // Custom array of category ID associated with unique logic. 
	public $applicationKywds = array(); // Custom array of keywords associated with unique logic. 
	public $applicationGroups = array(); // Custom array of Groups associated with unique logic. 
	

	
	// Used for ssl_encryption
	private $salt = 'w.+9(+/H%g*F3W=$swNGUwCY}&J=TG%F%}M:{s~:9*]3!Kh@rx_a[#C"M\n7';
	private $token = '\b9.UI}]t3Q1ZX"h'; // Initialization vector for SSL encrypt/decrypt. 
	
	private $endpoint = 'webnative/portalDI?';
	private $uid = NULL;
	private $pwd = NULL;
	private $userData;  
	private $allowedActions = array(
		'version',
		'showvols',
		'showusersettings',
		'showkywdperms',
		'showbaskbtns',
		'showiccusm',
		'clearbasket',
		'showdirinfo',
		'fileinfo',
		'showbasket',
		'addbasket',
		'removebasket',
		'upload',
		'getorderimage',
		'getimage',
		'navigator',
		'streamfile',
		'submitkywd',
		'filemgr',
		'annotations',
		'saveannotations',
		'browse',
		'presearch',
		'search'
	); 
	private $eventCodes = array(
		3 => 'CREATE',
		4 => 'DELETE',
		5 => 'RENAME',
		6 => 'READ',
		7 => 'WRITE',
		8 => 'COPY',
		9 => 'MKDIR',
		10 => 'RMDIR',
		11 => 'ADDCMT',
		12 => 'SETPARAM',
		13 => 'FPO',
		14 => 'WEBIMAGE',
		15 => 'QUARK',
		16 => 'PDF',
		18 => 'DOWNHIRES',
		19 => 'DOWNFPO',
		20 => 'DOWNPREV',
		21 => 'UPLOAD',
		22 => 'IMAGEORDER',
		23 => 'BACKEDUP',
		24 => 'ONLINE',
		25 => 'MEDIACHG',
		26 => 'TA PE DE',
		27 => 'PRINTED',
		28 => 'ARCHIVED',
		29 => 'DOSYNC',
		30 => 'TRIGGER',
		31 => 'METACHG',
		32 => 'WNA',
		33 => 'IMGREPL',
		34 => 'VIDEO',
		35 => 'DOWNVIDEO',
		36 => 'VIDVIEWED',
		37 => 'ANNOTNEW',
		38 => 'ANNOTEDIT',
		39 => 'ANNOTVIEW',
		40 => 'SETMETA',
		41 => 'DOXMPSYN',
		43 => 'ASSETSTART',
		44 => 'ASSETEXPIRED',
		45 => 'ASSETLOCKED',                    
		46 => 'ASSETUNLOCKED'
	); 
	private $reservedChars = array(';','/','\\','?',':','@','&','=','+','$',',','[',']'); // Todo replace with % escape sequence. 
	





	public function __construct($server){
		$this->server = $server; 
		
		try {
			if(!extension_loaded('openssl')){
				throw new Exception('Open SSL Extension required');	
			}
		} catch (Exception $e){
			echo $e->getMessage();
			exit();  	
		}
		 	
		
		if($_SESSION['userData']){
			$this->isAuth = true; 
			$this->uid = $_SESSION['userData']['uid']; 
			$this->pwd = openssl_decrypt($_SESSION['userData']['pwd'],'aes-256-ctr',$this->salt,OPENSSL_RAW_DATA,$this->token);   
			
			// Get Keyword Details/Permissons
			if(!isset($_SESSION['kywdData'])){
				$kywds = $this->request('showkywdperms',array(),'array');
				if(isset($kywds['KEYWORDS_INFO'])){
					foreach($kywds['KEYWORDS_INFO'] as $kywd){
						$kywdData[$kywd['KW_ID']] = array(
							'name' => $kywd['KW_NAME'],
							'desc' => $kywd['KW_DESC'],
							'length' => $kywd['KW_SIZE'],
							'format' => $kywd['KW_DISPLAY']
						);	
						if($kywdData[$kywd['KW_ID']]['format'] == '0'){
							unset($kywdData[$kywd['KW_ID']]['format']);	
						}
					}
					if(count($kywdData)) 
						$_SESSION['kywdData'] = $kywdData; 
				} 
			}
			
			
		}else{
			$this->isAuth = false;
			 
			
		}

	}
	
	public function __destruct(){
		
	}
	
	public function login($uid,$pwd){
		$this->uid = $uid; 
		$this->pwd = $pwd; 
		
		$response = $this->request('showusersettings',array(),'array'); 
		//var_dump($response); exit(); 
		if($response && isset($response['MAILTO'])){
			$_SESSION['userData'] = $response;
			// Need to store uid/pwd in session, need to pass it to the request object. This is dodgy as f*ck! 
			$_SESSION['userData']['uid'] = $uid;   
			$_SESSION['userData']['pwd'] = openssl_encrypt($pwd,'aes-256-ctr',$this->salt,OPENSSL_RAW_DATA,$this->token); 
			$this->isAuth = true;
		}else{
			$this->logout(); 
		}
		 
	}
	
	public function logout(){
		$this->isAuth = false;		
		$this->userData = NULL; 
		$this->uid = NULL; 
		$this->pwd = NULL; 
		unset($_SESSION['userData']); 
		unset($_SESSION['kywdData']); 
	}
	
	public function getVideo($fileID){
		ob_end_clean(); 
		ob_start(); 		
		echo $this->request('streamfile',array(
			'fileid' => $fileID,
			'videoid' => 0,
			'attach' => 'false'
		));
		ob_end_flush(); 
		exit(); 
	}
	
	public function userInGroup($groupName){
		$return = false; 
		$groups = $_SESSION['userData']['GROUPS']; 
		if(is_array($groups)){
			foreach($groups as $index => $group){
				if(strtolower($group['NAME']) == strtolower($groupName))
					$return = true; 	
			}
		}
		return $return; 
	}
	
	public function setThumbCacheDir($dir){
		/*
		echo 'Is Writeable '.$dir.'<br />'.PHP_EOL;
		var_dump(is_writeable($dir));
		exit();  
		*/
		if(is_dir($dir) && is_writeable($dir))
			$this->thumbCacheDir = $dir; 
	}
	
	public function getThumbCacheDir(){
		return $this->thumbCacheDir; 	
	}
	

	
	
	// Outputs image to browser, will check for locally cached version first. 
	
	public function getImage($args){
		
		// $args MUST only contain valid arguments that match the getimage API endpoint arguments list. 				
		$args = array_merge($args,array(
			'packerrors' => true,
			'bgcolor_r' => 85, // Dark grey background. 
			'bgcolor_g' => 85,
			'bgcolor_b' => 85,
			'debug' => 'true'
		));
		
		
		if($args['filetype'] == 'small'){ // Light grey background. 
			$args['bgcolor_r'] = 238;
			$args['bgcolor_g'] = 238;
			$args['bgcolor_b'] = 238;
		}
		
		
		
		$data = $this->request('getimage',$args); // Grab Binary Data. 
		
		
		
		
		if($this->cacheThumbs && $args['filetype'] == 'small'){
			// START: Construct cache filename to include mtime;  
			$imageInfo = $this->request('fileinfo',array(
				'fileid' => $args['fileid'],
				// Try and limit API roundtrip. 
				'showfiles' => 'true',
				'filesperpage' => 1,
				'page' => 1 
			),'array'); 
			$imageInfo = $imageInfo['FILES_INFO'][0];
			$mTime = $imageInfo['FILE_MDATE']; 
			$fileName = substr($imageInfo['FILE_NAME'],0,strrpos($imageInfo['FILE_NAME'],'.')); 
			$fileExt = substr($imageInfo['FILE_NAME'],strrpos($imageInfo['FILE_NAME'],'.')); 
			$localFile = $fileName.'_'.$mTime.$fileExt;
			file_put_contents($this->getThumbCacheDir().$localFile, $data, LOCK_EX);  
			// END: 
		}


		// OUTPUT	
		ob_end_clean(); 
		ob_start("ob_gzhandler");
		if(extension_loaded('gd')){ // GD Seems to be marginally quicker at rendering

			$img = @imagecreatefromstring($data); // Surpress error output, avoid contaminating output buffer. 

			header('Content-type:image/jpg'); // Image is always JPEG for Web Previews.  
			header('Pragma: public');
			header('Cache-Control: max-age=86400');
			header('Expires: '. gmdate('D, d M Y H:i:s \G\M\T', time() + 86400));		

			imagejpeg($img);
			imagedestroy($img);
			
			
		}else{
			
			header('Content-type:image/jpg'); // Image is always JPEG for Web Previews.  
			header('Pragma: public');
			header('Cache-Control: max-age=86400');
			header('Expires: '. gmdate('D, d M Y H:i:s \G\M\T', time() + 86400));		
			
			echo $data; 

		}
		
		ob_end_flush();  
		exit(); 	
					

	}
	
	
	
	
	
	// Forces file download
	public function downloadFile($fileID){

		// Get basic file data. 
		$fileData = $this->request('fileinfo',array(
			'fileid' => $fileID
		),'array');
		$fileData = $fileData['FILES_INFO'][0]; // ['PARENT_FILE_ID']
		
		$this->request('streamfile',array(
			'path' => urldecode($fileData['FILE_PATH']),
			'attach' => 'true',
			'_filelength' => $fileData['FILE_LENGTH'] // Not a valid query param, need to unset on request
		));
			
	}
	
	public function getEventCode($code){
		$code = (int)$code;
		return (isset($this->eventCodes[$code])) ? $this->eventCodes[$code] : NULL; 
	}	
	
	
	
	// @args $fileID (string)path or (int)fileID.
	// @args $limit (int)limit results returned. Highly recommended if this method is used in recursive loops. 
	public function getFiles($fileID,$limit=NULL){
		$assets = NULL; 
		$params = array(
			'showdirs' => 'false', // This method intended to ONLY return files... No dirs. 
			'showfiles' => 'true',
			'showkywds' => 'true'	
		);
		if(!Validate::fnIsNull($limit)){
			$params['filesperpage'] = $limit; 
			$params['filepage'] = $limit;
		}
			
		if(!ctype_digit($fileID)){
			$params['path'] = $fileID; 	
		}else{
			$params['fileid'] = $fileID;	
		}
		
		if(!Validate::fnIsNull($fileID)){
			$assets = $this->request('browse',$params,'array');	
		}
		
		return $assets; 
		//print_r($assets); 
	}

	
	
	// Valid $sReturnType = json || binary (for assets). 
	public function request($action,$args=array(),$responseType='json'){
		$response = NULL; 
		
		if($action=='streamfile' && isset($args['_filelength'])){
			$fileSize = $args['_filelength'];
			// Remove artificially injected argument. 
			unset($args['_filelength']); 
		}
		
		$args = array_filter($args)+array('action'=>$action);
		$this->request = $this->server; 
		$this->request .= $this->endpoint; 
		$this->request .= http_build_query($args);
		$curl = curl_init();
		
		/*
		if($action == 'submitkywd'){
			echo $this->request;
			//exit();  	
		}
		*/
		
		
		$options = array(
			CURLOPT_URL => $this->request,
			CURLOPT_HEADER => false, 
			CURLOPT_RETURNTRANSFER => true,
			CURLOPT_SSL_VERIFYPEER => false,
			CURLOPT_SSL_VERIFYHOST => false,
			CURLOPT_ENCODING => 'gzip,deflate', 
			CURLOPT_HTTPAUTH => CURLAUTH_BASIC, //CURLAUTH_ANY,
			CURLOPT_USERPWD => $this->uid.":".$this->pwd
		);
			
		curl_setopt_array($curl,$options);
		
		// Custom for streamfile only if attach(ment) == true; 
		if($action=='streamfile' && $args['attach'] == 'true'){
			
			header('Content-Type: application/octet-stream');	
			header('Content-Disposition: attachment; filename="'.basename($args['path']));	
			header('Content-Length: '.$fileSize);
			header('Content-Transfer-Encoding: binary');
			header('Content-Description: File Transfer');
			
			
			curl_setopt($curl, CURLOPT_WRITEFUNCTION, function($handle, $data) {
				echo $data;
				return strlen($data);
				exit(); 
			});
			
		}

		$response = curl_exec($curl);
		$statusCode = curl_getinfo($curl,CURLINFO_HTTP_CODE);
		$this->httpCode = $statusCode; 
			
		if(curl_errno($curl)){
			echo 'Curl error: ' . curl_error($curl);
		}else{
			if($statusCode == 200){
				switch($responseType){
					case 'json': 
						$response = $response; 
					break; 
					case 'array': 
						$response = json_decode($response,true);
					break;
				}
			}elseif($statusCode == 401){
				// Not Auth;  
				$response = NULL; 	
			}else{
				$response = NULL; 	
			}
		}
		
		/*
		echo 'uid: '.$this->uid; 
		echo 'request:' .$this->request; 
		exit();
		*/
		curl_close($curl);
		
		return $response; 
	
	}
	

	
		
}