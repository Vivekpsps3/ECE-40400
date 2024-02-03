#!/usr/bin/perl -w

##  find_differentials_correlations.pl

##  Avi Kak  (March 4, 2015)

##  This script creates a histogram of the mapping between the input differentials
##  and the output differentials for an SBox.  You have two choices for the SBox ---
##  as reflected by lines (B8) and (B9) of the script. For a given input byte, the
##  statement in line (B8) returns the MI (multiplicative inverse) of the byte in
##  GF(2^8) based on the AES modulus.  And the statement in line (B8) returns a byte
##  through a user-specified table lookup.  The table for this is specified in line
##  (A9).  More generally, such a table can be created by a random permutation
##  through the commented-out statements in lines (A7) and (A8).

use strict;
use Algorithm::BitVector;
use Graphics::GnuplotIF;
$|++;

my $debug = 1;
my $AES_modulus = Algorithm::BitVector->new(bitstring => '100011011');                   #(A1)

my $M = 64;                     # CHANGE THIS TO 256 FOR A COMPLETE CALCULATION          #(A2)
                                #   This parameter control the range of inputs
                                #   bytes for creating the differentials. With
                                #   its value set to 64, only the differentials
                                #   for the bytes whose int values are between 0
                                #   and 63 are tried.
#  Initialize the histogram:
my $differential_hist;                                                                   #(A3)
foreach my $i (0..255) {                                                                 #(A4)
    foreach my $j (0..255) {                                                             #(A5)
       $differential_hist->[$i][$j] = 0;                                                 #(A6)
    }
}

#  When SBox is based on lookup, we will use the "table" created by randomly
#  permuting the the number from 0 to 255:
#my $lookuptable = shuffle([0..255]);                                                    #(A7)
#my @lookuptable = @$lookuptable;                                                        #(A8)
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
                     201 117 127 107 176 226 135 123 82 15 64 90);                       #(A9)


#  This call creates the 2D plaintext/ciphertext differential histogram:
gen_differential_histogram();                                                            #(A10)

#  The call shown below will show that part of the histogram for which both 
#  the input and the output differentials are in the range (32, 63). 
display_portion_of_histogram(32, 64);                                                    #(A11)

plot_portion_of_histogram($differential_hist, 32, 64);                                   #(A12)
## The following call makes a hardcopy of the plot:
plot_portion_of_histogram($differential_hist, 32, 64, 3);                                #(A13)

sub gen_differential_histogram {                                                         #(B1)
    foreach my $i (0 .. $M-1) {                                                          #(B2)
        print "\ni=$i\n" if $debug;                                                      #(B3)
        foreach my $j (0 .. $M-1) {                                                      #(B4)
            print ". " if $debug;                                                        #(B5)
            my ($a, $b) = (Algorithm::BitVector->new(intVal => $i, size => 8),  
                           Algorithm::BitVector->new(intVal => $j, size => 8));          #(B6)
            my $input_differential = int($a ^ $b);                                       #(B7)
            #  Of the two statements shown below, you must comment out one depending
            #  on what type of an SBox you want:
#            my ($c, $d) = (get_sbox_output_MI($a), get_sbox_output_MI($b));             #(B8)
            my ($c, $d) = (get_sbox_output_lookup($a), get_sbox_output_lookup($b));      #(B9)
            my $output_differential = int($c ^ $d);                                      #(B10)
            $differential_hist->[$input_differential][$output_differential]++;           #(B11)
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

##################### Support Routines for Displaying the Histogram  ########################

#  Displays in your terminal window the bin counts in the two-dimensional histogram
#  for the input/output mapping of the differentials.  You can control the portion of
#  the 2D histogram that is output by using the first argument to set the lower bin
#  index and the second argument the upper bin index along both dimensions.
#  Therefore, what you see is always a square portion of the overall histogram.
sub display_portion_of_histogram {                                                       #(F1)
    my $lower = shift;                                                                   #(F2)
    my $upper = shift;                                                                   #(F3)
    foreach my $i ($lower .. $upper - 1) {                                               #(F4)
        print "\n";                                                                      #(F5)
        foreach my $j ($lower .. $upper - 1) {                                           #(F6)
            print "$differential_hist->[$i][$j] ";                                       #(F7)
        }
    }
}

#  Displays with a 3-dimensional plot a square portion of the histogram. Along both
#  the X and the Y directions, the lower bound on the bin index is supplied by the
#  SECOND argument and the upper bound by the THIRD argument.  The last argument is
#  needed only if you want to make a hardcopy of the plot.  The last argument is set
#  to the number of second the plot will be flashed in the terminal screen before it
#  is dumped into a `.png' file.
sub plot_portion_of_histogram { 
    my $hist = shift;                                                                    #(G1)
    my $lower = shift;                                                                   #(G2)
    my $upper = shift;                                                                   #(G3)
    my $pause_time = shift;                                                              #(G4)
    my @plot_points = ();                                                                #(G5)
    my $bin_width = my $bin_height = 1.0;                                                #(G6)
    my ($x_min, $y_min, $x_max, $y_max) = ($lower, $lower, $upper, $upper);              #(G7)
    foreach my $y ($y_min..$y_max-1) {                                                   #(G8)
        foreach my $x ($x_min..$x_max-1) {                                               #(G9)
            push @plot_points, [$x, $y, $hist->[$y][$x]];                                #(G10)
        }
    }
    @plot_points = sort {$a->[0] <=> $b->[0]} @plot_points;                              #(G11)
    @plot_points = sort {$a->[1] <=> $b->[1] if $a->[0] == $b->[0]} @plot_points;        #(G12)
    my $temp_file = "__temp.dat";                                                        #(G13)
    open(OUTFILE , ">$temp_file") or die "Cannot open temporary file: $!";               #(G14)
    my ($first, $oldfirst);                                                              #(G15)
    $oldfirst = $plot_points[0]->[0];                                                    #(G16)
    foreach my $sample (@plot_points) {                                                  #(G17)
        $first = $sample->[0];                                                           #(G18)
        if ($first == $oldfirst) {                                                       #(G19)
            my @out_sample;                                                              #(G20)
            $out_sample[0] =  $sample->[0];                                              #(G21)
            $out_sample[1] =  $sample->[1];                                              #(G22)
            $out_sample[2] =  $sample->[2];                                              #(G23)
            print OUTFILE "@out_sample\n";                                               #(G24)
        } else {                                                                         #(G25)
            print OUTFILE "\n";                                                          #(G26)
        }
        $oldfirst = $first;                                                              #(G27)
    }
    print OUTFILE "\n";             
    close OUTFILE;                                                                       
my $argstring = <<"END";                                                                 #(G28)
set xrange [$x_min:$x_max] 
set yrange [$y_min:$y_max] 
set view 80,15
set hidden3d               
splot "$temp_file" with lines
END
    unless (defined $pause_time) {                                                       #(G29)
        my $hardcopy_name =  "output_histogram.png";                                     #(G30)
        my $plot1 = Graphics::GnuplotIF->new();                                          #(G31)
        $plot1->gnuplot_cmd( 'set terminal png', "set output \"$hardcopy_name\"");       #(G32)
        $plot1->gnuplot_cmd( $argstring );                                               #(G33)
        my $plot2 = Graphics::GnuplotIF->new(persist => 1);                              #(G34)
       $plot2->gnuplot_cmd( $argstring );                                                #(G35)
    } else {                                                                             #(G36)
        my $plot = Graphics::GnuplotIF->new();                                           #(G37)
        $plot->gnuplot_cmd( $argstring );                                                #(G38)
        $plot->gnuplot_pause( $pause_time );                                             #(G39)
    }
}
