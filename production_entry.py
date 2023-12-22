from recover_range import recover_range_4_dependency


ranges = recover_range_4_dependency('org.jboss.logging|jboss-logging|3.4.2.Final', 'org.apache.logging.log4j|log4j-core|2.11.2')
print('\n', ranges)