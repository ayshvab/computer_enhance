#!/usr/bin/env ruby

require 'fileutils'

class TestRunner
  def initialize
    @pass_count = 0
    @fail_count = 0
    @test_cases = [
      "mov_reg_reg",
      "mov_reg_mem",
      "mov_mem_reg",
      "mov_reg_imm",
      "mov_mem_imm",
      "mov_segreg",
      
      # "add_reg_reg",
      # "add_reg_imm",
      # "add_reg_mem",
      # "add_mem_reg",
      # "add_mem_imm"
    ]
  end

  def run_all_tests
    build_project

    @test_cases.each { |test| run_test(test) }

    print_summary
    exit(@fail_count.zero? ? 0 : 1)
  end

  private

  def build_project
    Dir.chdir(File.dirname(__FILE__))
    system("../build.sh") || fail("Build failed")
  end

  def run_test(test_name)
    puts "\n=== Testing #{test_name} ==="

    asm_file = "#{test_name}.asm"
    baseline_bin = "#{test_name}.bin"
    disasm_file = "#{test_name}_disasm.asm"
    produced_bin = "#{test_name}_actual.bin"

    unless File.exist?(asm_file)
      puts "Assembly file '#{asm_file}' is missing. Skipping."
      @fail_count += 1
      return
    end

    unless system("nasm -f bin #{asm_file} -o #{baseline_bin}")
      puts "Baseline assembly failed"
      @fail_count += 1
      return
    end
    puts "Built baseline -> #{baseline_bin}"

    unless system("../_build/emu8086 #{baseline_bin} > #{disasm_file}")
      puts "Disassembly failed"
      @fail_count += 1
      return
    end
    puts "Disassembled -> #{disasm_file}"

    unless system("nasm -f bin #{disasm_file} -o #{produced_bin}")
      puts "Re-assembly failed"
      @fail_count += 1
      return
    end
    puts "Assembled disassembled code -> #{produced_bin}"

    show_hex_comparison(baseline_bin, produced_bin)

    if files_identical?(baseline_bin, produced_bin)
      puts "✓ PASS (binaries identical): #{test_name}"
      @pass_count += 1
    else
      puts "✗ FAIL (binaries differ): #{test_name}"
      show_hex_diff(test_name, baseline_bin, produced_bin)
      @fail_count += 1
    end
  end

  def show_hex_comparison(baseline_bin, produced_bin)
    puts "Baseline bytes (first 64):"
    system("head -c 64 #{baseline_bin} | hexdump -C")
    puts "\nProduced bytes (first 64):"
    system("head -c 64 #{produced_bin} | hexdump -C")
  end

  def files_identical?(file1, file2)
    return false unless File.exist?(file1) && File.exist?(file2)
    return false unless File.size(file1) == File.size(file2)
    
    File.binread(file1) == File.binread(file2)
  end

  def show_hex_diff(test_name, baseline_bin, produced_bin)
    puts "--- diff (hex dump full) ---"
    puts "Baseline: #{baseline_bin}"
    
    baseline_hex = "#{test_name}_baseline.hex"
    actual_hex = "#{test_name}_actual.hex"
    
    system("hexdump -C #{baseline_bin} > #{baseline_hex}")
    puts "Produced: #{produced_bin}"
    system("hexdump -C #{produced_bin} > #{actual_hex}")
    
    system("diff -u #{baseline_hex} #{actual_hex}") if system("which diff > /dev/null 2>&1")
  end

  def print_summary
    puts "\n=== SUMMARY ==="
    puts "PASSED: #{@pass_count}"
    puts "FAILED: #{@fail_count}"
    puts "TOTAL:  #{@pass_count + @fail_count}"

    if @fail_count.zero?
      puts "🎉 All tests passed!"
    else
      puts "❌ Some tests failed"
    end
  end
end

TestRunner.new.run_all_tests if __FILE__ == $0
