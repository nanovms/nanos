begin
  array = []
  start = Time.now
  while (Time.now - start) < 5
      array << "x" * (1024 * 1024)
  end
rescue => e
  puts "Memory exhausted: #{e}"
end
