import unittest
import subprocess
import os

class Emu8086DecoderTest(unittest.TestCase):
	def prepare_listing(self, listing_dir, listing):
		asm_file = os.path.join(listing_dir, ".".join([listing, "asm"]))
		binary_file = os.path.join("./test-tmp", listing)

		result = subprocess.run(["nasm", asm_file, "-o", binary_file], capture_output=True)
		result.check_returncode()

		result = subprocess.run(["./emu8086", binary_file], capture_output=True)
		result.check_returncode()

		emu8086_binary_file = os.path.join('./test-tmp', '__'.join(['emu8086', listing]))
		emu8086_asm_file = '.'.join([emu8086_binary_file, 'asm'])
		with open(emu8086_asm_file, mode='wb') as asm_file:
			asm_file.write(result.stdout)

		result = subprocess.run(["nasm", emu8086_asm_file, "-o", emu8086_binary_file], capture_output=True)
		result.check_returncode()
	
		result = subprocess.run(["diff", emu8086_binary_file, binary_file], capture_output=True)

		return result


	# def test__casey_listing_0037_single_register_mov(self):
	# 	self.assertEqual(self.prepare_listing('../part1', 'listing_0037_single_register_mov'), 0)

	def test__simple(self):
		self.assertEqual(self.prepare_listing('./test-data', 'simple').returncode, 0)						

if __name__ == '__main__':
	suite = unittest.TestSuite()

	if not os.path.exists("./test-tmp"):
		os.makedirs("./test-tmp")

	suite.addTest(unittest.makeSuite(Emu8086DecoderTest))

	runner = unittest.TextTestRunner(verbosity=2)
	runner.run(suite)
