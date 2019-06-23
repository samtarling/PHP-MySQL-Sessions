<?php

	/*
	Revised code by Dominick Lee
	Original code derived from "Essential PHP Security" by Chriss Shiflett
	Last Modified 2/27/2017


	CREATE TABLE sessions
	(
		id varchar(32) NOT NULL,
		access int(10) unsigned,
		data text,
		PRIMARY KEY (id)
	);

	+--------+------------------+------+-----+---------+-------+
	| Field  | Type             | Null | Key | Default | Extra |
	+--------+------------------+------+-----+---------+-------+
	| id     | varchar(32)      |      | PRI |         |       |
	| access | int(10) unsigned | YES  |     | NULL    |       |
	| data   | text             | YES  |     | NULL    |       |
	+--------+------------------+------+-----+---------+-------+

	*/


class Session {
	private $db;

	public function __construct($db, $options=array()){
		// Instantiate new Database object
		$this->db = $db;

		// Set handler to overide SESSION
		session_set_save_handler(
		array($this, "_open"),
		array($this, "_close"),
		array($this, "_read"),
		array($this, "_write"),
		array($this, "_destroy"),
		array($this, "_gc")
		);

                // Override default options by parameter
                $this->options = array_merge(
                  array(
                    'table' => 'sessions',
                  ),
                  $options
                );

		// Start the session
		session_start();
	}
	public function _open(){
		return true;
	}
	public function _close(){
                return true;
	}
	public function _read($id){
		// Set query
		$stmt = $this->db->prepare("SELECT data FROM {$this->options['table']} WHERE id = :id");
		// Bind the Id
		$stmt->bindValue(':id', $id, PDO::PARAM_STR);
		// Attempt execution
		// If successful
		if($stmt->execute()){
		// Save returned row
		$row = $stmt->fetch(PDO::FETCH_ASSOC);
                if (!$row) {
                  return '';
                }
		// Return the data
		return $row['data'];
		}else{
		// Return an empty string
		return '';
		}
	}
	public function _write($id, $data){
		// Set query  
		$stmt = $this->db->prepare("INSERT INTO {$this->options['table']} (id, ts_access, ts_create, data) VALUES (:id, now(), now(), :data) ON DUPLICATE KEY UPDATE count = count + 1, data = :data, ts_access = now()");
		// Bind data
		$stmt->bindValue(':id', $id, PDO::PARAM_STR);
		$stmt->bindValue(':data', $data, PDO::PARAM_STR);
		// Attempt Execution
		// If successful
		if($stmt->execute()){
		// Return True
		return true;
		}
		// Return False
		return false;
	}
	public function _destroy($id){
		// Set query
		$stmt = $this->db->prepare("DELETE FROM {$this->options['table']} WHERE id = :id");
		// Bind data
		$stmt->bindValue(':id', $id, PDO::PARAM_STR);
		// Attempt execution
		// If successful
		if($stmt->execute()){
		// Return True
		return true;
		}
		// Return False
		return false;
	} 
	public function _gc($max){
		// Calculate what is to be deemed old
		$old = time() - $max;
		// Set query
		$stmt = $this->db->prepare("DELETE FROM {$this->options['table']} WHERE access < :old");
		// Bind data
		$stmt->bindValue(':old', $old, PDO::PARAM_INT);
		// Attempt execution
		if($stmt->execute()){
		// Return True
		return true;
		}
		// Return False
		return false;
	}
}
?>
