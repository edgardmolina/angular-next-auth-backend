import { BadRequestException, Injectable, InternalServerErrorException, UnauthorizedException } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { JwtService } from '@nestjs/jwt';
import { Model } from 'mongoose';

import * as bcryptjs  from 'bcryptjs';

import { RegisterUserDto, CreateUserDto, UpdateAuthDto, LoginDto  } from './dto';

import { User } from './entities/user.entity';

import { JwtPayload } from './interfaces/pwt-payload';
//import { LoginResponse } from '../../dist/auth/interfaces/login-response';
import { LoginResponse } from './interfaces/login-response';

@Injectable()
export class AuthService {

  constructor(
    @InjectModel( User.name ) 
    private userModel: Model<User>,
    private jwtService: JwtService,
  ) {}

  async create( createUserDto: CreateUserDto ): Promise<User> {
    //console.log( createUserDto );
    try {
      // 1 encriptar contraseña
      const { password, ...userData } = createUserDto;
      const newUser = new this.userModel( {
        password: bcryptjs.hashSync( password, 10 ),
        ...userData
      });
      // 2 guardar usuario
      // 3 generar JWT (jaison web tokent)
      //return await newUser.save();
      await newUser.save();
      const { password:_, ...user } = newUser.toJSON();

      return user;

    } catch ( error ) {

      console.log( error.code );
      if( error.code = 11000 ){
        throw new BadRequestException( `${ createUserDto.email } already exists!` );
      }
      throw new InternalServerErrorException( 'Something terribe happend!!!' );
    }    
  }

  async register( registerDto : RegisterUserDto ) : Promise < LoginResponse > {
    //const user = await this.create( email : registerDto.email, name: );
    const user = await this.create( registerDto );
    console.log( { user } );
    return { 
      user  : user,
      token : this.getJwtToken( { id : user._id } )
    };
  }

  async login( loginDto : LoginDto ) : Promise< LoginResponse > {
    /**
     * User { _id, anme, email, roles,... }
     * token -> ASCDSF.ASDA,ASDASD"
     **/
    //console.log( { loginDto } );
    const {email, password } = loginDto;
    const user = await this.userModel.findOne( { email });
    if ( !user ) {
      throw new UnauthorizedException( 'Not valid credentials - email' );
    }
    if( !bcryptjs.compareSync( password, user.password ) ) {
      throw new UnauthorizedException( 'Not valid credentials - password' );
    }
    //return 'TODO BIEN!';
    const { password:_, ...rest } = user.toJSON();
    return { 
      user: rest,
      //token: 'ABC-123'
      token: this.getJwtToken( { id : user.id } ),
    };
  }

  findAll() : Promise<User[]> {
    //return `This action returns all auth`;
    return this.userModel.find();
  }

  async findUserById( id : string ){
    const user = await this.userModel.findById( id );
    const { password, ...rest }  = user.toJSON();
    return rest;
  }

  findOne(id: number) {
    return `This action returns a #${id} auth`;
  }

  update(id: number, updateAuthDto: UpdateAuthDto) {
    return `This action updates a #${id} auth`;
  }

  remove(id: number) {
    return `This action removes a #${id} auth`;
  }

  getJwtToken( payload : JwtPayload ){
    const token = this.jwtService.sign( payload ) ;
    return token;
  }
}
