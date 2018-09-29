__author__ = 'Kim Thomson'

from sip import setapi
setapi('QString', 2)

from PyQt4 import QtCore, QtGui, uic
from PyQt4.Qt import QMessageBox, QStatusBar

from sys import exit,argv
from hashlib import md5,sha1,sha256
from zlib import adler32
from string import maketrans, translate
from binascii import hexlify, unhexlify, crc32
from mac_mutate import mutator
from base64 import b64encode,b64decode


qtCreatorFile = "./ui/decoder.ui" # The decoder UI file

Ui_MainWindow, QtBaseClass = uic.loadUiType(qtCreatorFile)

class DecoderMain(QtGui.QMainWindow, Ui_MainWindow):
	def __init__(self):
		QtGui.QMainWindow.__init__(self)
		Ui_MainWindow.__init__(self)
		self.setupUi(self)
		#just sets the theme of the UI, in this case cleanlooks
		QtGui.QApplication.setStyle(QtGui.QStyleFactory.create('cleanlooks'))
		
		#menu options
		self.actionExit.triggered.connect(self.closeApplication)
		self.actionSave.triggered.connect(self.saveOutput)
		#buttons
		#all other button actions are handled via the UI directly
		self.execute_btn.clicked.connect(self.decoderSelect)
		self.save_btn.clicked.connect(self.saveOutput)
		
		#turn on statusBar below
		self.statusBar = QStatusBar()
		self.setStatusBar(self.statusBar)
		self.updateStatus()
		
		#initially set the hash and length options to disabled, unless
		#if the proper function is chosen, then enable the options
		#there are two things here, both of which serve fine
		#one hides the entire group, the other disables it
		self.hash_options_group.hide()
		#self.hash_options_group.setEnabled(False) #this just deactivates, but doesn't hide
		self.length_group.hide()
		
		#if the user changes the combo box, run the function to
		#update the show/hide or enable/disabled status of the
		#hash options and/or length options
		self.func_select.currentIndexChanged.connect(self.enableOptions)
		
	#close the application, however that may happen	
	def closeApplication(self):
		choice = QtGui.QMessageBox.question(self, 'Exit', 'Exit the Super Decoder?',\
									QtGui.QMessageBox.Yes | QtGui.QMessageBox.No)
		if choice == QtGui.QMessageBox.Yes:
			exit()
		else:
			return
	def updateStatus(self):
		message = 'Input Length: {}           Output Length: {}'.\
					format(len(self.input_line.text()),len(self.output_box.toPlainText()))
		self.statusBar.showMessage(message)
	
	#generic popup window for messages and good times	
	def popupWindow(self, title, message):
		self.msg = QMessageBox()
		self.msg.setIcon(QMessageBox.Information)
		self.msg.setWindowTitle(title)
		self.msg.setText(message)
		self.msg.setStandardButtons(QMessageBox.Ok)
		self.msg.exec_()
	
	#save whatever output data there is to a text file
	#if there is none, it won't save
	def saveOutput(self):
		output_text = unicode(self.output_box.toPlainText())
		if len(output_text) != 0:
			output_text = 'Input Text:\n{}\n\nOutput Text:\n{}'.format(self.input_line.text(),output_text)
			export_name = QtGui.QFileDialog.getSaveFileName(filter=self.tr("Text file (*.txt)"))
			if export_name != "":
				f = open(export_name, 'wb')
				f.write(output_text)
				f.close()
				self.popupWindow('File Saved', 'Data has been saved to {}.    '.format(export_name))
		else:
			self.popupWindow('No Data for Export','Sorry, there is no data to save.')
	
	#enable or disable the options groups for different functions
	def enableOptions(self):
		#hide or show hash options
		if self.func_select.currentText() == 'Hash Text':
			self.hash_options_group.show()
		else:
			self.hash_options_group.hide()

		#hide or show length options, depending on function
		#could do this as one big if statement, but...
		if self.func_select.currentText() == 'Hex to ASCII':
			self.length_group.show()
			self.pad_radio.hide()
		elif self.func_select.currentText() == 'Base64 Decode':
			self.length_group.show()
			self.pad_radio.show()
		elif self.func_select.currentText() == 'Reverse Nibble':
			self.length_group.show()
			self.pad_radio.show()
		elif self.func_select.currentText() == 'Switch Endianness':
			self.length_group.show()
			self.pad_radio.show()
		elif self.func_select.currentText() == 'Hex to Decimal IP':
			self.length_group.hide()
			self.pad_radio.hide()
		else:
			self.length_group.hide()

			
	#checks the state of the combo box "func_select"
	#to determine which function to run
	def decoderSelect(self):
		self.updateStatus()
		if self.func_select.currentText() == 'Decimal to Hex':
			self.decimaltoHex()
		elif self.func_select.currentText() == 'Decimal to Binary':
			self.decimaltoBinary()
		elif self.func_select.currentText() == 'ASCII to Hex':
			self.asciitoHex()
		elif self.func_select.currentText() == 'Hex to ASCII':
			self.hextoAscii()
		elif self.func_select.currentText() == 'Base64 Encode':
			self.base64Encode()
		elif self.func_select.currentText() == 'Base64 Decode':
			self.base64Decode()
		elif self.func_select.currentText() == 'Reverse Nibble':
			self.reverseNibble()
		elif self.func_select.currentText() == 'Switch Endianness':
			self.switchEndian()
		elif self.func_select.currentText() == 'ROT13':
			self.rot13()
		elif self.func_select.currentText() == 'Hash Text':
			self.hashText()
		elif self.func_select.currentText() == 'Find OUI Vendor':
			self.findOUIVendor()
		elif self.func_select.currentText() == 'Hex to Decimal IP':
			self.hexToDecIP()
	
	#convert decimal to hex, pad with leading zero if necessary
	def decimaltoHex(self):
		try:
			input_num = int(self.input_line.text())
		except ValueError:
			self.popupWindow('Invalid Input', 'Sorry, input is not proper decimal.    ')
			self.output_box.clear()
			return
		
		hex_num = hex(input_num)[2:]
		hex_num = '0' * (len(hex_num) % 2) + hex_num
		
		self.output_box.setText(hex_num.rstrip('L'))
		self.updateStatus()
	
	#convert decimal to binary, pad zeroes depending on bit length
	def decimaltoBinary(self):
		try:
			input_num = int(self.input_line.text())
		except ValueError:
			self.popupWindow('Invalid Input', 'Sorry, input is not proper decimal.    ')
			self.output_box.clear()
			return
		
		bits = input_num.bit_length()
		zero_pad = '0' * (4 - (bits % 4))
		
		bin_num = bin(input_num)[2:]
		bin_num = zero_pad + bin_num
		
		self.output_box.setText(bin_num)
		self.updateStatus()
		
	#encode base64		
	def base64Encode(self):
		input_text = unicode(self.input_line.text())
		output_text = b64encode(input_text)
		self.output_box.setText(output_text)
		self.updateStatus()
	
	#decode base64, check length, etc.
	def base64Decode(self):
		input_text = unicode(self.input_line.text())
		
		#check if the input has a length that's a multiple of 4
		#pad if necessary
		if len(input_text) % 4 != 0:
			pad_length = len(input_text) % 4
			input_text += '=' * pad_length
			self.input_line.setText(input_text)
			
		try:
			output_text = b64decode(input_text)
		except TypeError:
			self.output_box.clear()
			self.popupWindow('Invalid Input', 'Sorry, input is not proper base64.    ')
			return
		
		self.output_box.setText(output_text)
		self.updateStatus()

	#reverse nibble stuff, check length		
	def reverseNibble(self):
		input_text = unicode(self.input_line.text())
		
		#check to see if input length is multiple of 2
		#depending on the radio button selected, it 
		#will truncate, pad, or refuse to decode
		if len (input_text) % 2:
			if self.truncate_radio.isChecked():
				self.popupWindow('Improper Input Length',\
					'Input length is not a multiple of 2. Truncating.    ')
			elif self.pad_radio.isChecked():
				self.popupWindow('Improper Input Length',\
					'Input length is not a multiple of 2. Padding with "F".    ')
				input_text += "F"
			elif self.refuse_radio.isChecked():
				self.popupWindow('Improper Input Length',\
					'Input length is not a multiple of 2. Failure to decode.    ')
				self.output_box.clear()
				return
		
		output_text = ''.join([y+x for x,y in zip (*[iter(input_text)] * 2)])
		self.output_box.setText(output_text)
		self.updateStatus()
		
	#switch from LE to BE and vice versa
	def switchEndian(self):
		input_text = unicode(self.input_line.text())
		if len(input_text) == 0:
			return
		
		if len(input_text) % 2:
			if self.truncate_radio.isChecked():
				input_text = input_text[:-1]
				self.popupWindow('Improper Input Length',\
				'Input length is not a multiple of 2. Truncating.    ')
			elif self.pad_radio.isChecked():
				input_text += 'F'
				self.popupWindow('Improper Input Length',\
				'Input length is not a multiple of 2. Padding with "F".    ')
			elif self.refuse_radio.isChecked():
				self.popupWindow('Improper Input Length',\
				'Input length is not a multiple of 2. Failure to decode.    ')
				self.output_box.clear()
				return
		
		self.output_box.setText("".join(reversed([input_text[i:i+2] for i in range(0, len(input_text), 2)])))
		self.updateStatus()

	#get all the hashes of the input text
	def hashText(self):
		input_text = unicode(self.input_line.text())
		output_text = ''
	
		if self.crc32_check.isChecked():
			crc32_hash = hex((crc32(input_text) + (1 << 32)) % (1 << 32))[2:-1].upper().zfill(8)
			output_text += 'CRC32 Hash: {}\n'.format(crc32_hash)
		if self.adler_check.isChecked():
			adler32_hash = hex(adler32(input_text))[2:].upper().zfill(8)
			output_text += 'Adler32 Hash: {}\n'.format(adler32_hash)
		if self.md5_check.isChecked():
			md5_hash = md5(input_text).hexdigest()
			output_text += 'MD5 Hash: {}\n'.format(md5_hash)
		if self.sha1_check.isChecked():
			sha1_hash = sha1(input_text).hexdigest()
			output_text += 'SHA1 Hash: {}\n'.format(sha1_hash)
		if self.sha256_check.isChecked():
			sha256_hash = sha256(input_text).hexdigest()
			output_text += 'SHA256 Hash: {}\n'.format(sha256_hash)
		if self.b64_256_check.isChecked():
			sha256_64_hash = b64encode(sha256(input_text).digest())
			output_text += 'Base64 SHA256 Hash: {}\n'.format(sha256_64_hash)

		self.output_box.setText(output_text.rstrip())
		self.updateStatus()

	#get a vendor for a given mac address or OUI using sqlite db
	def findOUIVendor(self):
		
		#remove colons, dashes, uppercase and only take first 3 bytes (6 characters when it's text)
		input_text = unicode(self.input_line.text()).replace(':', '').replace('-', '').upper()[0:6]
		
		#just gonna see if it's hex or not by trying to int it
		try:
			int(input_text, 16)
		except ValueError:
			self.popupWindow('Invalid Input', 'Sorry, input is not a proper MAC or OUI.    ')
			self.output_box.clear()
			return

		result = mutator(input_text)
		output_text = 'Original OUI:   {}\nMatching OUI:   {}\nVendor:   {}\nMutation:   {}\n'.\
						format(result[0], result[1], result[2], result[3])
		self.output_box.setText(output_text)
		self.updateStatus()
	
	#convert ascii to hex
	def asciitoHex(self):
		input_text = self.input_line.text().encode('utf8')
		output_text = hexlify(input_text).upper()
		self.output_box.setText(output_text)
		self.updateStatus()
	
	#convert hex to ascii, check for validity
	def hextoAscii(self):
		valid_chars = 'ABCDEF0123456789'
		
		input_text = unicode(self.input_line.text())
		
		if all (c in valid_chars for c in input_text):
			if len (input_text) % 2:
				if self.truncate_radio.isChecked():
					self.popupWindow('Improper Input Length',\
						'Input length is not a multiple of 2. Truncated.    ')
					input_text = input_text[:-1]
				elif self.refuse_radio.isChecked():
					self.popupWindow('Improper Input Length',\
					'Input length is not a multiple of 2. Failure to decode.    ')
					self.output_box.clear()
					return
		#check for valid characters (A-F and 0-9) from valid_chars above
		
			output_text = str(unhexlify(input_text))
			self.output_box.setText(output_text)
			self.updateStatus()
		else:
			self.popupWindow('Invalid Input', 'Sorry, input is not proper hexadecimal.    ')
			self.output_box.clear()
			
	def rot13(self):
		try:
			input_text = unicode(self.input_line.text()).encode('ascii')
		except UnicodeEncodeError:
			self.popupWindow('Invalid Input', 'Sorry, input is not properly formatted.    ')
			self.output_box.clear()
			return
		rot13 = maketrans("ABCDEFGHIJKLMabcdefghijklmNOPQRSTUVWXYZnopqrstuvwxyz",\
									"NOPQRSTUVWXYZnopqrstuvwxyzABCDEFGHIJKLMabcdefghijklm")
		output_text = translate(input_text, rot13)
		self.output_box.setText(output_text)
		self.updateStatus()
		
	#needs error checking... not finished
	def hexToDecIP(self):
		input_text = str(self.input_line.text())
		flipped_ip = ("".join(reversed([input_text[i:i+2] for i in range(0, len(input_text), 2)])))
		output_text = ":".join([str(int(flipped_ip[x:x+2], 16)) for x in range(0,8,2)])
		self.output_box.setText(output_text)
			
if __name__ == "__main__":
	app = QtGui.QApplication(argv)
	window = DecoderMain()
	window.show()
	exit(app.exec_())