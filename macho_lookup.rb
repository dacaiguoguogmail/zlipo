require 'macho'
# 看文档可以从binarystirng读取，非常好
# https://www.rubydoc.info/gems/ruby-macho/MachO/MachOFile#filename-instance_method


file = MachO::FatFile.new("/opt/LibRepo/LvmmBSSupport/FrameworkLocation/LvmmBSSupport.framework/LvmmBSSupport")

# get the file's type (object, dynamic lib, executable, etc)
file.filetype # => :execute
puts file.filetype

file.fat_archs.each { |e| 
    puts "#{e.cputype} #{e.size}"
}
# get all load commands in the file and print their offsets:
# file.load_commands.each do |lc|
#   puts "#{lc.type}: offset #{lc.offset}, size: #{lc.cmdsize}"
# end

# # access a specific load command
# lc_vers = file[:LC_VERSION_MIN_MACOSX].first
# puts lc_vers.version_string # => "10.10.0"