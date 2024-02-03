#!/usr/bin/perl -w

##  linear_approximation_table_generator.pl

##  Avi Kak  (March 5, 2015)

##  This script demonstrates how to generate the Linear Approximation Table that is
##  needed for mounting a Linear Attack on a block cipher.

use strict;
use Algorithm::BitVector;
use Graphics::GnuplotIF;
$|++;

my $debug = 1;
my $AES_modulus = Algorithm::BitVector->new(bitstring => '100011011');                   #(A1)

#  Initialize LAT:
my $linear_approximation_table;                                                          #(A2)
foreach my $i (0..255) {                                                                 #(A3)
    foreach my $j (0..255) {                                                             #(A4)
       $linear_approximation_table->[$i][$j] = 0;                                        #(A5)
    }
}

#  When SBox is based on lookup, we will use the "table" created by randomly
#  permuting the the number from 0 to 255:
#my $lookuptable = shuffle([0..255]);                                                    #(A6)
#my @lookuptable = @$lookuptable;                                                        #(A7)
my @lookuptable = qw(213 170 104 116 66 14 76 219 200 42 22 17 241 197 41 216 85 140 
                     183 244 235 6 118 208 74 218 99 44 1 89 11 205 195 125 47 236 113 
                     237 131 109 102 9 21 220 59 154 119 148 38 120 13 217 16 100 191 81 
                     240 196 122 83 177 229 142 35 88 48 167 0 29 153 163 146 166 77 79 
                     43 10 194 232 189 238 164 204 111 69 51 126 62 211 242 70 214 247 55 
                     202 78 239 114 184 112 228 84 152 187 45 49 175 58 253 72 95 19 37 
                     73 145 87 198 71 159 34 91 168 250 255 8 121 96 50 141 181 67 26 243 
                     130 68 61 24 105 210 172 139 136 128 157 133 80 93 39 2 143 161 186 33 
                     144 178 30 92 138 169 86 249 252 155 193 63 223 203 245 129 4 171 
                     115 3 40 151 7 188 231 174 25 23 207 180 56 46 206 215 227 162 199 
                     97 147 182 149 108 36 132 5 12 103 110 209 160 137 53 224 185 173 
                     20 222 246 28 179 134 75 254 57 60 234 52 165 225 248 31 230 156 
                     124 233 158 27 18 94 65 32 54 106 192 221 190 101 98 251 212 150 
                     201 117 127 107 176 226 135 123 82 15 64 90);                       #(A8)


gen_linear_approximation_table();                                                        #(A9)

#  The call shown below will show that part of the LAT for which both the input and
#  the output bit grouping integers are in the range (0, 32):
display_portion_of_LAT(0, 32);                                                           #(A10)

#  This call makes a graphical plot for a portion of the LAT.  The bit grouping index
#  ranges for both the input and the output bytes are 32 to 64:
plot_portion_of_LAT($linear_approximation_table, 32, 64);                                #(A11)
## The following call makes a hardcopy of the plot:
plot_portion_of_LAT($linear_approximation_table, 32, 64, 3);                             #(A12)

#  You have two choices for the SBox in lines (B4) and (B5).  The one is line (B4) is
#  uses MI in GF(2^8) based on the AES modulus.  And the one in line (B5) uses the
#  lookup table defined above in line (A8). Comment out the one you do not want.
sub gen_linear_approximation_table {
    foreach my $x (0 .. 255) {               # specify a byte for the input to the SBox  #(B1)
        print "\input byte = $x\n" if $debug;                                            #(B2)
        my $a = Algorithm::BitVector->new(intVal => $x, size => 8);                      #(B3)
        #  Now get the output byte for the SBox:
        my $c = get_sbox_output_MI($a);                                                  #(B4)
#        my $c = get_sbox_output_lookup($a);                                             #(B5)
        my $y = int($c);                                                                 #(B6)
        foreach my $bit_group_from_x (0 .. 255) {                                        #(B7)
            my @input_bit_positions;                                                     #(B8)
            foreach my $pos (0..7) {                                                     #(B9)
                push @input_bit_positions, $pos if ($bit_group_from_x >> $pos) & 1;      #(B10)
            }                                                                            #(B11)
            my $input_linear_sum = 0;                                                    #(B12)
            foreach my $pos (@input_bit_positions) {                                     #(B13)
                $input_linear_sum ^= (($x >> $pos) & 1);                                 #(B14)
            }                                            
            foreach my $bit_group_from_y (0 .. 255) {                                    #(B15)
                my @output_bit_positions;                                                #(B16)
                foreach my $pos (0..7) {                                                 #(B17)
                    push @output_bit_positions, $pos if ($bit_group_from_y >> $pos) & 1; #(B18)
                }
                my $output_linear_sum = 0;                                               #(B19)
                foreach my $pos (@output_bit_positions) {                                #(B20)
                    $output_linear_sum ^= (($y >> $pos) & 1);                            #(B21)
                }
                $linear_approximation_table->[$bit_group_from_x][$bit_group_from_y]++    #(B22)
                     if $input_linear_sum == $output_linear_sum;                         #(B23)
            }
        }
    }
    foreach my $i (0 .. 255) {                                                           #(B24)
        foreach my $j (0 .. 255) {                                                       #(B25)
            $linear_approximation_table->[$i][$j] -= 128;                                #(B26)
        }
    }
}

sub get_sbox_output_MI {                                                                 #(C1)
    my $in = shift;                                                                      #(C2)
    return int($in) != 0 ? $in->gf_MI($AES_modulus, 8) :                                 #(C3)
                        Algorithm::BitVector->new(intVal => 0);                          #(C4)
}

sub get_sbox_output_lookup {                                                             #(D1)
    my $in = shift;                                                                      #(D2)
    return Algorithm::BitVector->new(intVal => $lookuptable[int($in)], size => 8);       #(D3)
}

# Fisher-Yates shuffle:                                                                        
sub shuffle {                                                                            #(E1)
    my $arr_ref = shift;                                                                 #(E2)
    my $i = @$arr_ref;                                                                   #(E3)  
    while (  $i-- ) {                                                                    #(E4)
        my $j = int rand( $i + 1 );                                                      #(E5)  
        @$arr_ref[ $i, $j ] = @$arr_ref[ $j, $i ];                                       #(E6)
    }                                                                                    #(E7)   
    return $arr_ref;                                                                     #(E8)  
}

######################### Support Routines for Displaying LAT  ##############################

#  Displays in your terminal window the bin counts (minus 128) in the LAT calculated
#  in lines (B1) through (B26). You can control the portion of the display by using
#  the first argument to set the lower bin index and the second argument the upper
#  bin index along both dimensions.  Therefore, what you see is always a square
#  portion of the LAT.
sub display_portion_of_LAT {                                                             #(F1)
    my $lower = shift;                                                                   #(F2)
    my $upper = shift;                                                                   #(F3)
    foreach my $i ($lower .. $upper - 1) {                                               #(F4)
        print "\n";                                                                      #(F5)
        foreach my $j ($lower .. $upper - 1) {                                           #(F6)
            print "$linear_approximation_table->[$i][$j] ";                              #(F7)
        }
    }
}

#  Displays with a 3-dimensional plot a square portion of the LAT. Along both the X
#  and the Y directions, the lower bound on the bin index is supplied by the SECOND
#  argument and the upper bound by the THIRD argument.  The last argument is needed
#  only if you want to make a hardcopy of the plot.  The last argument is set to the
#  number of second the plot will be flashed in the terminal screen before it is
#  dumped into a `.png' file.
sub plot_portion_of_LAT {                                                                #(G1)
    my $hist = shift;                                                                    #(G2)
    my $lower = shift;                                                                   #(G3)
    my $upper = shift;                                                                   #(G4)
    my $pause_time = shift;                                                              #(G5)
    my @plot_points = ();                                                                #(G6)
    my $bin_width = my $bin_height = 1.0;                                                #(G7)
    my ($x_min, $y_min, $x_max, $y_max) = ($lower, $lower, $upper, $upper);              #(G8)
    foreach my $y ($y_min..$y_max-1) {                                                   #(G9)
        foreach my $x ($x_min..$x_max-1) {                                               #(G10)
            push @plot_points, [$x, $y, $hist->[$y][$x]];                                #(G11)
        }
    }
    @plot_points = sort {$a->[0] <=> $b->[0]} @plot_points;                              #(G12)
    @plot_points = sort {$a->[1] <=> $b->[1] if $a->[0] == $b->[0]} @plot_points;        #(G13)
    my $temp_file = "__temp.dat";                                                        #(G14)
    open(OUTFILE , ">$temp_file") or die "Cannot open temporary file: $!";               #(G15)
    my ($first, $oldfirst);                                                              #(G16)
    $oldfirst = $plot_points[0]->[0];                                                    #(G17)
    foreach my $sample (@plot_points) {                                                  #(G18)
        $first = $sample->[0];                                                           #(G19)
        if ($first == $oldfirst) {                                                       #(G20)
            my @out_sample;                                                              #(G21)
            $out_sample[0] =  $sample->[0];                                              #(G22)
            $out_sample[1] =  $sample->[1];                                              #(G23)
            $out_sample[2] =  $sample->[2];                                              #(G24)
            print OUTFILE "@out_sample\n";                                               #(G25)
        } else {                                                                         #(G26)
            print OUTFILE "\n";                                                          #(G27)
        }
        $oldfirst = $first;                                                              #(G28)
    }
    print OUTFILE "\n";             
    close OUTFILE;                                                                       
my $argstring = <<"END";                                                                 #(G29)
set xrange [$x_min:$x_max] 
set yrange [$y_min:$y_max] 
set view 80,15
set hidden3d               
splot "$temp_file" with lines
END
    unless (defined $pause_time) {                                                       #(G30)
        my $hardcopy_name =  "LAT.png";                                                  #(G31)
        my $plot1 = Graphics::GnuplotIF->new();                                          #(G32)
        $plot1->gnuplot_cmd( 'set terminal png', "set output \"$hardcopy_name\"");       #(G33)
        $plot1->gnuplot_cmd( $argstring );                                               #(G34)
        my $plot2 = Graphics::GnuplotIF->new(persist => 1);                              #(G35)
       $plot2->gnuplot_cmd( $argstring );                                                #(G36)
    } else {                                                                             #(G37)
        my $plot = Graphics::GnuplotIF->new();                                           #(G38)
        $plot->gnuplot_cmd( $argstring );                                                #(G39)
        $plot->gnuplot_pause( $pause_time );                                             #(G40)
    }
}
